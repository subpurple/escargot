from typing import Tuple, Any, Optional, List, Set
import time
import re
import secrets
import asyncio
from email.parser import Parser

from util.misc import Logger, first_in_iterable
from core.models import User, MessageData, MessageType, NetworkID
from core.backend import Backend, BackendSession, ChatSession, Chat
from core import event, error
from .misc import Err, encode_capabilities_capabilitiesex, decode_email_pop, is_blocking
from .msnp import MSNPCtrl

class MSNPCtrlSB(MSNPCtrl):
	__slots__ = ('backend', 'dialect', 'loop', 'counter_task', 'auth_sent', 'bs', 'cs')
	
	backend: Backend
	dialect: int
	loop: Optional[asyncio.AbstractEventLoop]
	counter_task: Optional[asyncio.Task]
	auth_sent: bool
	bs: Optional[BackendSession]
	cs: Optional[ChatSession]
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.loop = None
		self.counter_task = None
		self.auth_sent = False
		self.bs = None
		self.cs = None
	
	def on_connect(self) -> None:
		self.counter_task = asyncio.ensure_future(self._conn_auth_limit_counter())
	
	def _on_close(self) -> None:
		if self.counter_task is not None and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		if self.cs:
			self.cs.close()
	
	# State = Auth
	
	def _m_usr(self, trid: Optional[str], arg: Optional[str], token: Optional[str], *args: Any) -> None:
		#>>> USR trid email@example.com token (MSNP < 16)
		#>>> USR trid email@example.com;{00000000-0000-0000-0000-000000000000} token (MSNP >= 16)
		self.auth_sent = True
		if None in (trid,arg,token) or len(args) > 0: self.close(hard = True)
		
		(email, pop_id) = decode_email_pop(arg)
		
		data = self.backend.auth_service.pop_token('sb/xfr', token) # type: Optional[Tuple[BackendSession, int]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
		bs, dialect = data
		if bs.user.email != email or (dialect >= 16 and pop_id is not None and bs.front_data.get('msn_pop_id') != pop_id[1:-1]):
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
		chat = self.backend.chat_create()
		
		try:
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task is not None and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		chat._idle_counter_reset_callback = self._reset_cs_idle_mins
		self.counter_task = asyncio.ensure_future(self._add_idle_min_to_chat())
		self.send_reply('USR', trid, 'OK', arg, cs.user.status.name or cs.user.email)
	
	def _m_ans(self, trid: Optional[str], arg: Optional[str], token: Optional[str], sessid: Optional[int], *args: Any) -> None:
		#>>> ANS trid email@example.com token sessionid (MSNP < 18)
		#>>> ANS trid email@example.com;{00000000-0000-0000-0000-000000000000} token sessionid (MSNP >= 18)
		self.auth_sent = True
		if None in (trid,arg,token,sessid) or len(args) > 0: self.close(hard = True)
		
		(email, pop_id) = decode_email_pop(arg)
		
		data = self.backend.auth_service.get_token('sb/cal', token) # type: Optional[Tuple[BackendSession, int, Chat]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
		# expiry = self.backend.auth_service.get_token_expiry('sb/cal', token)
		# self.backend.auth_service.pop_token('sb/cal', token)
		# if round(expiry - time.time()) >= 60:
		# 	self.close(hard = True)
		
		(bs, dialect, chat) = data
		if bs.user.email != email or (dialect >= 16 and pop_id is not None and bs.front_data.get('msn_pop_id') != pop_id[1:-1]):
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
		
		if chat is None or sessid != chat.ids.get('main'): self.close(hard = True)
		
		try:
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex), trid)
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		
		chat.send_participant_joined(cs)
		
		roster_chatsessions = list(chat.get_roster()) # type: List[ChatSession]
		
		if dialect >= 16:
			tmp = [] # type: List[Tuple[ChatSession, Optional[str]]]
			for other_cs in roster_chatsessions:
				if other_cs.user.email == bs.user.email: continue
				for added_cs in tmp:
					if added_cs.user.email == other_cs.user.email: continue
				tmp.append(other_cs)
			l = len(tmp)
			for i, other_cs in enumerate(tmp):
				other_user = other_cs.user
				if dialect >= 18:
					capabilities = encode_capabilities_capabilitiesex(other_cs.bs.front_data.get('msn_capabilities') or 0, other_cs.bs.front_data.get('msn_capabilitiesex') or 0)
				else:
					capabilities = other_cs.bs.front_data.get('msn_capabilities') or 0
				
				self.send_reply('IRO', trid, i + 1, l, other_user.email, other_user.status.name, capabilities)
		else:
			roster_one_per_user = [] # type: List[ChatSession]
			seen_users = { self.cs.user } # type: Set[User]
			for other_cs in roster_chatsessions:
				if other_cs.user in seen_users:
					continue
				seen_users.add(other_cs.user)
				roster_one_per_user.append(other_cs)
			l = len(roster_one_per_user)
			for i, other_cs in enumerate(roster_one_per_user):
				other_user = other_cs.user
				extra = () # type: Tuple[Any, ...]
				if dialect >= 12:
					extra = (other_cs.bs.front_data.get('msn_capabilities') or 0,)
				self.send_reply('IRO', trid, i + 1, l, other_user.email, other_user.status.name, *extra)
		
		self.send_reply('ANS', trid, 'OK')
	
	# State = Live
	
	def _m_cal(self, trid: str, invitee_email: str) -> None:
		#>>> CAL trid email@example.com
		cs = self.cs
		assert cs is not None
		
		if cs.chat._idle_counter_reset_callback is not None:
			cs.chat._idle_counter_reset_callback()
		
		if not re.match(r'^[a-zA-Z0-9._\-]+@([a-zA-Z0-9\-]+\.)+[a-zA-Z]+$', invitee_email):
			self.send_reply(Err.InvalidPrincipal2, trid)
			return
		
		invitee_uuid = self.backend.util_get_uuid_from_email(invitee_email, NetworkID.WINDOWS_LIVE)
		if invitee_uuid is None:
			self.send_reply(Err.PrincipalNotOnline, trid)
			return
		
		chat = cs.chat
		try:
			bs = self.bs
			assert bs is not None
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			invitee = self.backend._load_user_record(invitee_uuid)
			if is_blocking(invitee, user) or invitee.status.is_offlineish():
				raise error.ContactNotOnline()
			
			cs.invite(invitee)
		except Exception as ex:
			# WLM 2009 sends a `CAL` with the invitee being the owner when a SB session is first initiated. If there are no other
			# PoPs of the owner, send a `JOI` for now to fool the client.
			# TODO: Find better way to check for exception to determine if fake `JOI` should be sent, as checking if `ex` is `error.ContactAlreadyOnList()` doesn't work.
			if ex is error.ContactAlreadyOnList and invitee_email == self.bs.user.email and self.dialect >= 18:
				# self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
				cs.evt.on_participant_joined(cs)
				return
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		else:
			self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
	
	def _m_msg(self, trid: str, ack: str, data: bytes) -> None:
		#>>> MSG trid [UNAD] len
		bs = self.bs
		assert bs is not None
		cs = self.cs
		assert cs is not None
		
		if cs.chat._idle_counter_reset_callback is not None:
			cs.chat._idle_counter_reset_callback()
		
		if len(data) > 1664:
			self.close(hard = True)
			return
		
		cs.send_message_to_everyone(messagedata_from_msnp(cs.user, bs.front_data.get('msn_pop_id'), data))
		
		# TODO: Implement ACK/NAK
		if ack == 'U':
			return
		any_failed = False
		if any_failed: # ADN
			self.send_reply('NAK', trid)
		elif ack != 'N': # AD
			self.send_reply('ACK', trid)
	
	def _check_sb_idle_criteria(self) -> None:
		more_than_2_invitees = False
		roster_other_cs = []
		roster_cs_pops = []
		
		if not self.cs.chat.idle_mins >= 5: return
		for cs_other in self.cs.chat.get_roster():
			if cs_other.user is not self.cs.user:
				roster_other_cs.append(cs_other)
			elif cs_other.user is self.cs.user and cs_other is not self.cs:
				roster_cs_pops.append(cs_other)
		
		if not roster_other_cs:
			self.close(hard = True)
			return
		
		second_party_pops = [roster_other_cs[0]] # type: List[ChatSession]
		for cs_rest in roster_other_cs[1:]:
			if cs_rest.user is second_party_pops[0].user:
				second_party_pops.append(cs_rest)
			else:
				more_than_2_invitees = True
		
		if more_than_2_invitees:
			del second_party_pops
			if not self.cs.chat.idle_mins >= 15: return
			if self.counter_task is not None and not self.counter_task.cancelled():
				self.counter_task.cancel()
				self.counter_task = None
			user_to_bye = roster_other_cs[secrets.randbelow(len(roster_other_cs))].user
			user_to_bye_sessions = [sess_other for sess_other in roster_other_cs if sess_other.user.uuid == user_to_bye.uuid]
			for sess_to_bye in user_to_bye_sessions:
				sess_to_bye.close(idle = True, send_idle_leave = True)
			for other_cs in roster_other_cs:
				if other_cs is not self.cs:
					other_cs.close(idle = True, send_idle_leave = False)
			self.cs.close(idle = True, send_idle_leave = False)
		else:
			for second_user_cs in second_party_pops:
				for cs_pop in roster_cs_pops:
					second_user_cs.evt.on_participant_left(cs_pop, idle = True, last_pop = False)
				second_user_cs.evt.on_participant_left(self.cs, idle = True, last_pop = True)
				second_user_cs.close(idle = True, send_idle_leave = True)
			self.cs.close(idle = True, send_idle_leave = False)
	
	async def _conn_auth_limit_counter(self) -> None:
		counter = 0
		
		while counter < 1:
			await asyncio.sleep(60)
			counter += 1
		
		if counter == 1:
			if not self.auth_sent:
				self.close(hard = True)
	
	async def _add_idle_min_to_chat(self) -> None:
		while True:
			#TODO: SB idle counter working properly?
			print('Original minute(s) idle:', self.cs.chat.idle_mins)
			await asyncio.sleep(60)
			self.cs.chat.idle_mins += 1
			print('New minute(s) idle:', self.cs.chat.idle_mins)
			self._check_sb_idle_criteria()
	
	def _reset_cs_idle_mins(self) -> None:
		if self.counter_task is not None and not self.counter_task.cancelled():
			self.counter_task.cancel()
		
		self.cs.chat.idle_mins = 0
		
		self.counter_task = asyncio.ensure_future(self._add_idle_min_to_chat())

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl',)
	
	ctrl: MSNPCtrlSB
	
	def __init__(self, ctrl: MSNPCtrlSB) -> None:
		self.ctrl = ctrl
	
	def on_participant_joined(self, cs_other: ChatSession) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		cs = self.cs
		
		if 12 <= ctrl.dialect <= 18:
			extra = (cs_other.bs.front_data.get('msn_capabilities') or 0,) # type: Tuple[Any, ...]
		elif ctrl.dialect >= 18:
			extra = (encode_capabilities_capabilitiesex(cs_other.bs.front_data.get('msn_capabilities') or 0, cs_other.bs.front_data.get('msn_capabilitiesex') or 0),)
		else:
			extra = ()
		user = cs_other.user
		ctrl.send_reply('JOI', user.email, user.status.name, *extra)
	
	def on_participant_left(self, cs_other: ChatSession, idle: bool, last_pop: bool) -> None:
		ctrl = self.ctrl
		if not last_pop and ctrl.dialect < 16: return
		pop_id_other = cs_other.bs.front_data.get('msn_pop_id')
		if pop_id_other is not None and ctrl.dialect >= 16:
			email = '{};{}'.format(cs_other.user.email, '{' + pop_id_other + '}')
		else:
			email = cs_other.user.email
		if idle:
			extra = (1,) # type: Tuple[Any, ...]
		else:
			extra = ()
		self.ctrl.send_reply('BYE', email, *extra)
	
	def on_invite_declined(self, invited_user: User, *, message: Optional[str] = None) -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		self.ctrl.send_reply('MSG', data.sender.email, data.sender.status.name, messagedata_to_msnp(data))
	
	def on_close(self, keep_future: bool, idle: bool):
		self.ctrl.close(hard = idle)

def messagedata_from_msnp(sender: User, sender_pop_id: Optional[str], data: bytes) -> MessageData:
	# TODO: Implement these `Content-Type`s:
	# voice:
	# b'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgsinvite; charset=UTF-8\r\n\r\nInvitation-Command: CANCEL\r\nCancel-Code: TIMEOUT\r\nInvitation-Cookie: 126868552\r\nSession-ID: {CE64F989-2AAD-44C4-A780-2C55A812B0B6}\r\nConn-Type: Firewall\r\nSip-Capability: 1\r\n\r\n'
	# xfer:
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n\x00\x00\x00\x00Gt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\xb2\x04\x00\x00\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00INVITE MSNMSGR:t2h@hotmail.com MSNSLP/1.0\r\nTo: <msnmsgr:t2h@hotmail.com>\r\nFrom: <msnmsgr:t1h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 0 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\nMax-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 948\r\n\r\nEUF-GUID: {5D3E02AB-6190-11D3-BBBB-00C04F795683}\r\nSessionID: 180646677\r\nAppID: 2\r\nContext: fgIAAAMAAAAAAAAAAAAAAAEAAABhAC4AdAB4AHQAA...AAAAAAAAA/////wAAAAAAAAAAAAAAAAAAA\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n\x00\x00\x00\x00Gt\xc4\n\xb2\x04\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n\x00\x00\x00\x00Wt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00Gt\xc4\nwn\xc5\n\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# xfer decline:
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n\x00\x00\x00\x00Xt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00N\x0b\xc7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00MSNSLP/1.0 603 Decline\r\nTo: <msnmsgr:t1h@hotmail.com>\r\nFrom: <msnmsgr:t2h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 1 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\nMax-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 25\r\n\r\nSessionID: 180646677\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n\x00\x00\x00\x00Ht\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00Xt\xc4\nN\x0b\xc7\nK\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# etc.
	
	message_mime = Parser().parsestr(data.decode('utf-8'))
	
	if message_mime['Content-Type'] is 'text/x-msmsgscontrol':
		type = MessageType.Typing
		text = ''
	elif message_mime['Content-Type'] is 'text/plain':
		type = MessageType.Chat
		text = message_mime.get_payload()
	else:
		type = MessageType.Chat
		text = "(Unsupported MSNP Content-Type)"
	
	message = MessageData(sender = sender, type = type, text = text)
	message.front_cache['msnp'] = data
	return message

def messagedata_to_msnp(data: MessageData) -> bytes:
	if 'msnp' not in data.front_cache:
		if data.type is MessageType.Typing:
			s = F'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgscontrol\r\nTypingUser: {data.sender.email}\r\n\r\n\r\n'
		elif data.type is MessageType.Chat:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n' + (data.text or '')
		else:
			raise ValueError("unknown message type", data.type)
		data.front_cache['msnp'] = s.encode('utf-8')
	return data.front_cache['msnp']
