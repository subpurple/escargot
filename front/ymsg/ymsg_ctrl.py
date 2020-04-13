import io
from abc import ABCMeta, abstractmethod
import asyncio
from typing import Dict, Tuple, Any, Optional, Callable, Iterable
import binascii
import struct
import settings

from core import error
from util.misc import Logger, MultiDict
from .misc import YMSGStatus, YMSGService

KVS = MultiDict[bytes, bytes]

class YMSGCtrlBase(metaclass = ABCMeta):
	__slots__ = ('logger', 'decoder', 'encoder', 'peername', 'closed', 'close_callback', 'transport')
	
	logger: Logger
	decoder: 'YMSGDecoder'
	encoder: 'YMSGEncoder'
	peername: Tuple[str, int]
	close_callback: Optional[Callable[[], None]]
	closed: bool
	transport: Optional[asyncio.WriteTransport]
	
	def __init__(self, logger: Logger) -> None:
		self.logger = logger
		self.decoder = YMSGDecoder(logger)
		self.encoder = YMSGEncoder(logger)
		self.peername = ('0.0.0.0', 5050)
		self.closed = False
		self.close_callback = None
		self.transport = None
	
	def data_received(self, data: bytes, *, transport: Optional[asyncio.BaseTransport] = None) -> None:
		if transport is None:
			transport = self.transport
		assert transport is not None
		self.peername = transport.get_extra_info('peername')
		for y in self.decoder.data_received(data):
			try:
				# check version and vendorId
				if y[1] > 16 or y[2] not in (0, 100):
					return
				f = getattr(self, '_y_{}'.format(binascii.hexlify(struct.pack('!H', y[0])).decode()))
				f(*y[1:])
			except Exception as ex:
				self.logger.error(ex)
	
	def send_reply(self, service: YMSGService, status: YMSGStatus, session_id: int, kvs: Optional[KVS] = None) -> None:
		try:
			self.encoder.encode(service, status, session_id, kvs)
		except error.DataTooLargeToSend:
			return
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def flush(self) -> bytes:
		return self.encoder.flush()
	
	def close(self, **kwargs: Any) -> None:
		if self.closed: return
		self.closed = True
		
		if self.close_callback:
			self.close_callback()
		self._on_close(**kwargs)
	
	@abstractmethod
	def _on_close(self, remove_sess_id: bool = True) -> None: pass

class YMSGEncoder:
	__slots__ = ('_logger', '_buf')
	
	_logger: Logger
	_buf: io.BytesIO
	
	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()
	
	def encode(self, service: YMSGService, status: YMSGStatus, session_id: int, kvs: Optional[KVS] = None) -> None:
		payload_list = []
		if kvs is not None:
			k = None # type: Optional[bytes]
			v = None # type: Optional[bytes]
			for k, v in kvs.items():
				payload_list.extend([k, SEP, v, SEP])
		payload = b''.join(payload_list)
		
		# TODO: Yahoo!'s servers used to split large payloads into packet chunks,
		# but there's little information on how it was exactly handled.
		# Just drop packets if they're too big (for the length field to handle unfortunately) until we can find a solution.
		
		if len(payload) > 0xffff:
			raise error.DataTooLargeToSend()
		
		w = self._buf.write
		w(PRE)
		# version number and vendor id are replaced with 0x00000000
		w(b'\x00\x00\x00\x00')
		
		# Have to call `int` on these because they might be an IntEnum, which
		# get `repr`'d to `EnumName.ValueName`. Grr.
		w(struct.pack('!HHII', len(payload), int(service), int(status), session_id))
		w(payload)
		
		self._logger.info('<<<', service, status, session_id)
		if kvs:
			_truncated_kvs(service, kvs)
	
	def flush(self) -> bytes:
		data = self._buf.getvalue()
		if data:
			#self._logger.info('<<<', data)
			self._buf = io.BytesIO()
		return data

DecodedYMSG = Tuple[YMSGService, int, int, YMSGStatus, int, KVS]

class YMSGDecoder:
	__slots__ = ('logger', '_data', '_i')
	
	logger: Logger
	_data: bytes
	_i: int
	
	def __init__(self, logger: Logger) -> None:
		self.logger = logger
		self._data = b''
		self._i = 0
	
	def data_received(self, data: bytes) -> Iterable[DecodedYMSG]:
		if self._data:
			self._data += data
		else:
			self._data = data
		while self._data:
			y = self._ymsg_read()
			if y is None: break
			yield y
	
	def _ymsg_read(self) -> Optional[DecodedYMSG]:
		try:
			y, e = _try_decode_ymsg(self._data, self._i)
		except AssertionError:
			return None
		except Exception:
			print("ERR _ymsg_read", self._data)
			raise
		
		self._data = self._data[e:]
		self._i = 0
		self.logger.info('>>>',  'YMSG{}'.format(str(y[1])), y[0], y[3], y[4])
		_truncated_kvs(y[0], y[5])
		return y

def _try_decode_ymsg(d: bytes, i: int) -> Tuple[DecodedYMSG, int]:
	kvs = MultiDict() # type: KVS
	
	e = 20
	assert len(d[i:]) >= e
	assert d[i:i+4] == PRE
	header = d[i+4:i+e]
	if header[:2] in (b'\x08\x00',b'\x09\x00',b'\x0a\x00'):
		version = struct.unpack('<H', header[:2])[0] # type: int
	else:
		version = struct.unpack('!H', header[:2])[0]
	(vendor_id, n, service, status, session_id) = struct.unpack('!HHHII', header[2:]) # type: Tuple[int, int, int, int, int]
	assert version in YMSG_DIALECTS
	assert e+n <= len(d[i:])
	payload = d[e:e+n]
	if payload:
		assert payload[-2:] == SEP
		parts = payload.split(SEP)
		del parts[-1]
		assert len(parts) % 2 == 0
		for j in range(1, len(parts), 2):
			kvs.add(parts[j-1], parts[j])
		e += n
	return ((YMSGService(service), version, vendor_id, YMSGStatus(status), session_id, kvs), e)

def _truncated_kvs(service: YMSGService, kvs: KVS) -> None:
	restricted_keys = set()
	
	if service in (YMSGService.AuthResp, YMSGService.List):
		restricted_keys.add(b'59')
	if service in (
		YMSGService.Message, YMSGService.MassMessage, YMSGService.ContactNew, YMSGService.FriendAdd,
		YMSGService.ContactDeny, YMSGService.ConfDecline, YMSGService.ConfMsg,YMSGService.P2PFileXfer, YMSGService.FileTransfer
	):
		restricted_keys.add(b'14')
	if service in (YMSGService.ConfInvite, YMSGService.ConfAddInvite):
		restricted_keys.add(b'58')
	if service in (YMSGService.P2PFileXfer, YMSGService.FileTransfer):
		restricted_keys.add(b'20')
	
	if settings.DEBUG and settings.DEBUG_YMSG:
		for k, v in kvs.items():
			 print('{!r} -> {}'.format(k, (v if k not in restricted_keys else '<truncated>')))

PRE = b'YMSG'
SEP = b'\xC0\x80'

YMSG_DIALECTS = [
	# Actually supported
	10, 9,
	# Not actually supported
	16, 15, 14, 13, 12, 11, 8,
]
