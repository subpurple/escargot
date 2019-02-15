import io
from abc import ABCMeta, abstractmethod
import asyncio
from typing import Dict, List, Tuple, Any, Optional, Callable, Iterable
from multidict import MultiDict
import binascii
import struct
import time

from util.misc import Logger

from .misc import YMSGStatus, YMSGService

KVS = Dict[str, str]

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
	
	def data_received(self, transport: asyncio.BaseTransport, data: bytes) -> None:
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
		self.encoder.encode(service, status, session_id, kvs)
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def flush(self) -> bytes:
		return self.encoder.flush()
	
	def close(self) -> None:
		if self.closed: return
		self.closed = True
		
		if self.close_callback:
			self.close_callback()
		self._on_close()
	
	@abstractmethod
	def _on_close(self) -> None: pass

class YMSGEncoder:
	__slots__ = ('_logger', '_buf')
	
	_logger: Logger
	_buf: io.BytesIO
	
	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()
	
	def encode(self, service: YMSGService, status: YMSGStatus, session_id: int, kvs: Optional[KVS] = None) -> None:
		w = self._buf.write
		w(PRE)
		# version number and vendor id are replaced with 0x00000000
		w(b'\x00\x00\x00\x00')
		
		_truncated_log(self._logger, '<<<', (service, 0, 0, status, session_id, kvs), 'OUTGOING')
		
		payload_list = []
		if kvs is not None:
			for k, v in kvs.items():
				payload_list.extend([str(k).encode('utf-8'), SEP, str(v).encode('utf-8'), SEP])
		payload = b''.join(payload_list)
		# Have to call `int` on these because they might be an IntEnum, which
		# get `repr`'d to `EnumName.ValueName`. Grr.
		w(struct.pack('!HHII', len(payload), int(service), int(status), session_id))
		w(payload)
	
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
		_truncated_log(self.logger, '>>>', y, 'INCOMING')
		return y

def _try_decode_ymsg(d: bytes, i: int) -> Tuple[DecodedYMSG, int]:
	kvs = MultiDict()
	
	e = 20
	assert len(d[i:]) >= e
	assert d[i:i+4] == PRE
	header = d[i+4:i+e]
	if header[0] != b'\x00':
		version = struct.unpack('<H', header[:2])[0]
	else:
		version = struct.unpack('!H', header[:2])[0]
	(vendor_id, n, service, status, session_id) = struct.unpack('!HHHII', header[2:])
	assert version in YMSG_DIALECTS
	assert e+n <= len(d[i:])
	payload = d[e:e+n]
	if payload:
		assert payload[-2:] == SEP
		parts = payload.split(SEP)
		del parts[-1]
		assert len(parts) % 2 == 0
		for i in range(1, len(parts), 2):
			key = str(parts[i-1].decode())
			kvs.add(key, parts[i].decode('utf-8'))
		e += n
	return ((YMSGService(service), version, vendor_id, YMSGStatus(status), session_id, kvs), e)

def _truncated_log(logger: Logger, pre: str, y: DecodedYMSG, transport_type: str) -> None:
	if y[0] in (YMSGService.List,YMSGService.P2PFileXfer,YMSGService.Message,YMSGService.ConfInvite,YMSGService.ConfAddInvite,YMSGService.ConfMsg,YMSGService.SkinName) or (y[0] in (YMSGService.FriendAdd,YMSGService.ContactDeny) and y[5].get('14') not in (None,'')) or (y[0] is YMSGService.ContactNew and y[3] in (YMSGStatus.NotAtHome,YMSGStatus.OnVacation) and y[5].get('14') not in (None,'')) or (y[0] is YMSGService.AuthResp and y[5].get('59') is not None):
		if transport_type == 'INCOMING':
			logger.info(pre, 'YMSG' + str(y[1]), y[0], y[3], y[4])
		elif transport_type == 'OUTGOING':
			logger.info(pre, y[0], y[3], y[4])
	else:
		if transport_type == 'INCOMING':
			logger.info(pre, 'YMSG' + str(y[1]), y[0], y[3], y[4], y[5])
		elif transport_type == 'OUTGOING':
			logger.info(pre, y[0], y[3], y[4], y[5])

PRE = b'YMSG'
SEP = b'\xC0\x80'

YMSG_DIALECTS = [
	# Actually supported
	10, 9,
	# Not actually supported
	16, 15, 14, 13, 12, 11, 8,
]
