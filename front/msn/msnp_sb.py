from typing import Tuple, Any, Optional, List, Set
import time
import secrets
import asyncio

from util.misc import Logger
from core.models import User, MessageData, MessageType
from core.backend import Backend, BackendSession, ChatSession, Chat
from core import event, error
from .misc import Err, encode_capabilities_capabilitiesex, decode_email_pop
from .msnp import MSNPCtrl

class MSNPCtrlSB(MSNPCtrl):
	__slots__ = ('backend', 'dialect', 'counter_task', 'auth_sent', 'bs', 'cs')
	
	backend: Backend
	dialect: int
	counter_task: Optional[asyncio.Task]
	auth_sent: bool
	bs: Optional[BackendSession]
	cs: Optional[ChatSession]
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.counter_task = None
		self.auth_sent = False
		self.bs = None
		self.cs = None
	
	def on_connect(self) -> None:
		self.counter_task = self.backend.loop.create_task(self._conn_auth_limit_counter())
	
	def _on_close(self) -> None:
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
		if bs.user.email != email or (dialect >= 16 and bs.front_data.get('msn_pop_id') != pop_id[1:-1]):
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
		chat = self.backend.chat_create()
		
		try:
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex), trid)
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		# self.counter_task.cancel()
		# self.counter_task = self.backend.loop.create_task(self._add_idle_min_to_cs())
		self.send_reply('USR', trid, 'OK', arg, cs.user.status.name)
	
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
		# self.counter_task.cancel()
		# self.counter_task = self.backend.loop.create_task(self._add_idle_min_to_cs())
		
		chat.send_participant_joined(cs)
		
		roster_chatsessions = list(chat.get_roster()) # type: List[ChatSession]
		
		if dialect >= 16:
			# TODO: Messaging doesn't seem to work in WLM 2009, whether `IRO` and `MSG` contain the email handle combined with the
			# MPoP GUID or not.
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
				if dialect >= 13:
					extra = (other_cs.bs.front_data.get('msn_capabilities') or 0,)
				self.send_reply('IRO', trid, i + 1, l, other_user.email, other_user.status.name, *extra)
		
		self.send_reply('ANS', trid, 'OK')
	
	# State = Live
	
	def _m_cal(self, trid: str, invitee_email: str) -> None:
		#>>> CAL trid email@example.com
		cs = self.cs
		assert cs is not None
		
		# self._reset_cs_idle_mins()
		
		invitee_uuid = self.backend.util_get_uuid_from_email(invitee_email)
		if invitee_uuid is None:
			self.send_reply(Err.InvalidUser)
			return
		
		chat = cs.chat
		try:
			bs = self.bs
			assert bs is not None
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ctc = detail.contacts.get(invitee_uuid)
			if ctc is None:
				if user.uuid != invitee_uuid: raise error.ContactDoesNotExist()
				invitee = user
			else:
				if ctc.status.is_offlineish(): raise error.ContactNotOnline()
				invitee = ctc.head
			
			cs.invite(invitee)
		except Exception as ex:
			# WLM 2009 sends a `CAL` with the invitee being the owner when a SB session is first initiated. If there are no other
			# PoPs of the owner, send a `JOI` for now to fool the client.
			# TODO: Find better way to check for exception to determine if fake `JOI` should be sent, as checking if `ex` is `error.ContactAlreadyOnList()` doesn't work.
			if Err.GetCodeForException(ex) == Err.PrincipalOnList and invitee_email == self.bs.user.email and self.dialect >= 18:
				# self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
				cs.evt.on_participant_joined(cs)
				return
			self.send_reply(Err.GetCodeForException(ex), trid)
		else:
			self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
	
	def _m_msg(self, trid: str, ack: str, data: bytes) -> None:
		#>>> MSG trid [UNAD] len
		bs = self.bs
		assert bs is not None
		cs = self.cs
		assert cs is not None
		
		# self._reset_cs_idle_mins()
		
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
		
		if not self.cs.idle_mins >= 5: return
		for cs_other in self.cs.chat.get_roster():
			if cs_other.user is not self.cs.user:
				roster_other_cs.append(cs_other)
			elif cs_other.user is self.cs.user and not cs_other.idle_mins >= 5:
				return
		
		if not roster_other_cs:
			self.close(hard = True)
			return
		
		second_party_pops = [roster_other_cs[0]] # type: List[ChatSession]
		for cs_rest in roster_other_cs[1:]:
			if cs_rest.user is second_party_pops[0].user:
				second_party_pops.append(cs_rest)
			else:
				more_than_2_invitees = True
		
		if more_than_2_invitees and self.cs.user is self.cs.chat.get_roster()[0].user:
			del second_party_pops
			if not self.cs.idle_mins >= 15: return
			for cs_other in self.cs.chat.get_roster():
				if not cs_other.idle_mins >= 15: return
			self.counter_task.cancel()
			user_to_bye = roster_other_cs[secrets.randbelow(len(roster_other_cs))]
			user_to_bye.evt.ctrl.counter_task.cancel()
			user_to_bye.close(idle = True)
			for other_cs in roster_other_cs:
				if other_cs is not self.cs:
					other_cs.evt.ctrl.counter_task.cancel()
					other_cs.close(hard = True)
			self.cs.close(hard = True)
		else:
			for second_user_cs in second_party_pops:
				idle_5_mins = second_user_cs.idle_mins >= 5
				if not idle_5_mins: break
			if idle_5_mins:
				self.counter_task.cancel()
				self.cs.close(idle = True)
	
	async def _conn_auth_limit_counter(self) -> None:
		counter = 0
		
		while counter < 1:
			await asyncio.sleep(60)
			counter += 1
		
		if counter == 1:
			if not self.auth_sent:
				self.close(hard = True)
	
	async def _add_idle_min_to_cs(self) -> None:
		await asyncio.sleep(60)
		
		while True:
			self.cs.idle_mins += 1
			self._check_sb_idle_criteria()
	
	def _reset_cs_idle_mins(self) -> None:
		self.counter_task.cancel()
		
		for cs in self.cs.chat.get_roster():
			cs.idle_mins = 0
		
		self.counter_task = self.backend.loop.create_task(self._add_idle_min_to_cs())

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
		
		if ctrl.dialect < 18:
			extra = (cs_other.bs.front_data.get('msn_capabilities') or 0,) # type: Tuple[Any, ...]
		elif ctrl.dialect >= 18:
			extra = (encode_capabilities_capabilitiesex(cs_other.bs.front_data.get('msn_capabilities') or 0, cs_other.bs.front_data.get('msn_capabilitiesex') or 0),)
		else:
			extra = ()
		user = cs_other.user
		ctrl.send_reply('JOI', user.email, user.status.name, *extra)
	
	def on_participant_left(self, cs_other: ChatSession, idle: bool = False) -> None:
		ctrl = self.ctrl
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
	
	def on_close(self, *args):
		self.ctrl.close()

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
	
	i = data.index(b'\r\n\r\n')
	headers = data[:i].decode('utf-8')
	body = data[i+4:]
	
	if 'text/x-msmsgscontrol' in headers:
		type = MessageType.Typing
		text = ''
	elif 'text/plain' in headers:
		type = MessageType.Chat
		text = body.decode('utf-8')
	else:
		type = MessageType.Chat
		text = "(Unsupported MSNP Content-Type)"
	
	message = MessageData(sender = sender, type = type, text = text)
	message.front_cache['msnp'] = data
	message.front_cache['msn_pop_id'] = sender_pop_id
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
