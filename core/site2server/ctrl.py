from typing import Tuple, Optional, Iterable, List, Any, Callable, Dict
import asyncio
import io

from core.backend import Backend
from core.models import GroupChatRole
from core import error
from util.misc import Logger, VoidTaskType
from util.hash import gen_salt

import settings

class S2SCtrl:
	__slots__ = (
		'logger', 'reader', 'writer', 'peername', 'close_callback', 'closed', 'transport',
		'authenticated', 'current_challenge', 'alive', 'alive_task', 'backend',
	)
	
	logger: Logger
	reader: 'S2SReader'
	writer: 'S2SWriter'
	peername: Tuple[str, int]
	close_callback: Optional[Callable[[], None]]
	closed: bool
	transport: Optional[asyncio.WriteTransport]
	authenticated: bool
	current_challenge: Optional[str]
	alive: bool
	alive_task: Optional[VoidTaskType]
	backend: Backend
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		self.logger = logger
		self.reader = S2SReader(logger)
		self.writer = S2SWriter(logger)
		self.peername = ('0.0.0.0', 4309)
		self.close_callback = None
		self.closed = False
		self.transport = None
		
		self.authenticated = False
		self.current_challenge = None
		self.alive = True
		self.alive_task = None
		self.backend = backend
	
	def _m_linksrv(self, password: str) -> None:
		backend = self.backend
		
		if backend._linked:
			self.send_numeric(Err.AlreadyAuthenticated)
			return
		
		if password == settings.SITE_LINK_PASSWORD:
			self.authenticated = True
			backend._linked = True
			
			self.alive_task = backend.loop.create_task(self._ping_conn())
			self.send_reply('LINKSRV', 'SUCCESS')
		else:
			self.send_numeric(Err.AuthenticationFailed)
			self.close()
	
	def _m_pong(self, challenge: str) -> None:
		if self.alive: return
		if not self.current_challenge or challenge != self.current_challenge:
			self.close()
			return
		self.alive = True
		self.current_challenge = None
	
	def _m_grpchat(self, ts: str, chat_id: str, action: str, *args: str) -> None:
		backend = self.backend
		
		if not self.authenticated:
			self.send_numeric(Err.NotAuthenticated)
			self.close()
			return
		
		groupchat = backend.user_service.get_groupchat(chat_id)
		
		if groupchat is None:
			self.send_numeric(Err.GroupChatDoesNotExist, ':GRPCHAT {}'.format(ts))
			return
		
		if action == 'INCHAT':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			try:
				in_chat = backend.util_user_online_in_groupchat(groupchat, user)
				self.send_reply('GRPCHAT', ts, 'INCHAT', uuid, str(in_chat))
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
			return
		elif action == 'ACCEPT':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			try:
				backend.util_accept_groupchat_invite(groupchat, user)
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.MemberAlreadyInGroupChat:
				self.send_numeric(Err.MemberAlreadyInGroupChat, ':GRPCHAT {}'.format(ts))
				return
		elif action == 'DECLINE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			try:
				backend.util_decline_groupchat_invite(groupchat, user)
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.MemberAlreadyInGroupChat:
				self.send_numeric(Err.MemberAlreadyInGroupChat, ':GRPCHAT {}'.format(ts))
				return
		elif action == 'REVOKE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			try:
				backend.util_revoke_groupchat_invite(groupchat, user)
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.MemberAlreadyInGroupChat:
				self.send_numeric(Err.MemberAlreadyInGroupChat, ':GRPCHAT {}'.format(ts))
				return
		elif action == 'ROLE':
			if len(args) < 2:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			user_self = None
			uuid = args[0]
			role_num = args[1]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			if len(args) >= 3:
				uuid_self = args[2]
				user_self = backend._load_user_record(uuid_self)
				if user_self is None:
					self.send_numeric(Err.UserNotInDB, ':{}'.format(ts))
					return
			
			try:
				role = GroupChatRole(int(role_num))
				if user_self is not None and role is not GroupChatRole.Admin: raise ValueError()
				
				backend.util_change_groupchat_membership_role(groupchat, user, role, user_self)
			except ValueError:
				self.send_numeric(Err.GroupChatRoleInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.GroupChatMemberIsPending:
				self.send_numeric(Err.GroupChatMemberIsPending, ':GRPCHAT {}'.format(ts))
				return
			except error.MemberDoesntHaveSufficientGroupChatRole:
				self.send_numeric(Err.DoesntHaveSufficientPermissions, ':GRPCHAT {}'.format(ts))
				return
		elif action == 'REMOVE':
			if len(args) < 1:
				self.send_numeric(Err.TooFewArguments, ':GRPCHAT {}'.format(ts))
				return
			
			uuid = args[0]
			
			user = backend._load_user_record(uuid)
			if user is None:
				self.send_numeric(Err.UserNotInDB, ':GRPCHAT {}'.format(ts))
				return
			
			try:
				backend.util_remove_user_from_groupchat(groupchat, user)
			except error.MemberNotInGroupChat:
				self.send_numeric(Err.GroupChatMemberInvalid, ':GRPCHAT {}'.format(ts))
				return
			except error.CantLeaveGroupChat:
				self.send_numeric(Err.CantLeaveGroupChat, ':GRPCHAT {}'.format(ts))
				return
		else:
			self.send_numeric(Err.InvalidArgument, ':GRPCHAT {}'.format(ts))
			return
		
		self.send_numeric(StatusCode.GroupChatActionSuccessful, ':GRPCHAT {}'.format(ts))
	
	def _m_quit(self) -> None:
		self.send_reply('QUIT')
		self.close()
	
	async def _ping_conn(self) -> None:
		while True:
			await asyncio.sleep(60)
			if self.closed or not self.alive:
				if not self.alive:
					self.close()
				break
			self.alive = False
			self.current_challenge = gen_salt()
			self.send_reply('PING', ':{}'.format(self.current_challenge))
	
	def data_received(self, transport: asyncio.BaseTransport, data: bytes) -> None:
		self.peername = transport.get_extra_info('peername')
		for m in self.reader.data_received(data):
			try:
				f = getattr(self, '_m_{}'.format(m[0].lower()))
				f(*m[1:])
			except Exception as ex:
				self.logger.error(ex)
	
	def send_numeric(self, n: int, *m: str) -> None:
		self.send_reply('{:03}'.format(n), *m)
	
	def send_reply(self, *m: str) -> None:
		self.writer.write(m)
		transport = self.transport
		if transport is not None:
			transport.write(self.flush())
	
	def flush(self) -> bytes:
		return self.writer.flush()
	
	def close(self) -> None:
		if self.closed: return
		self.closed = True
		if self.alive_task is not None and not self.alive_task.cancelled:
			self.alive_task.cancel()
		if self.authenticated:
			self.backend._linked = False
		if self.close_callback:
			self.close_callback()

class S2SReader:
	__slots__ = ('_logger', '_data')
	
	_logger: Logger
	_data: bytes
	
	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._data = b''
	
	def data_received(self, data: bytes) -> Iterable[List[str]]:
		if self._data:
			self._data += data
		else:
			self._data = data
		while self._data:
			m = self._read()
			if m is None: break
			self._logger.info('>>>', *m)
			yield m
	
	def _read(self) -> Optional[List[str]]:
		try:
			i = self._data.index(b'\r\n')
		except IndexError:
			return None
		except ValueError:
			return None
		chunk = self._data[:i].decode('utf-8')
		self._data = self._data[i+2:]
		
		toks = []
		while True:
			chunk = chunk.lstrip(' ')
			if chunk[:1] == ':':
				toks.append(chunk[1:])
				break
			k = chunk.find(' ')
			if k < 0:
				tok = chunk
			else:
				tok = chunk[:k]
				chunk = chunk[k:]
			if tok:
				toks.append(tok)
			if k < 0:
				break
		return toks

class S2SWriter:
	__slots__ = ('_logger', '_buf')
	
	_logger: Logger
	_buf: io.BytesIO
	
	def __init__(self, logger: Logger) -> None:
		self._logger = logger
		self._buf = io.BytesIO()
	
	def write(self, m: Iterable[Any]) -> None:
		self._logger.info('<<<', *m)
		self._buf.write(' '.join(map(str, m)).encode('utf-8'))
		self._buf.write(b'\r\n')
	
	def flush(self) -> bytes:
		data = self._buf.getvalue()
		if data:
			self._buf = io.BytesIO()
		return data

# `1xx`: Generic codes; `2xx`: Group chat codes

class Err:
	AlreadyAuthenticated = 100
	AuthenticationFailed = 101
	NotAuthenticated = 102
	UserNotInDB = 103
	InvalidArgument = 104
	TooFewArguments = 105
	GroupChatDoesNotExist = 200
	GroupChatRoleInvalid = 202
	GroupChatMemberInvalid = 203
	MemberAlreadyInGroupChat = 204
	GroupChatMemberIsPending = 205
	DoesntHaveSufficientPermissions = 206
	CantLeaveGroupChat = 207

class StatusCode:
	GroupChatActionSuccessful = 201
