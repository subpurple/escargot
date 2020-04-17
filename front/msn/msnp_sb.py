from typing import Tuple, Any, Optional, List, Set
import time
import asyncio
from email.parser import Parser

from util.misc import Logger, VoidTaskType
from core.models import User, MessageData, MessageType, Substatus
from core.backend import Backend, BackendSession, ChatSession, Chat
from core import event, error
from .misc import Err, encode_capabilities_capabilitiesex, decode_email_pop, encode_email_pop, normalize_pop_id, MAX_CAPABILITIES_BASIC
from .msnp import MSNPCtrl

class MSNPCtrlSB(MSNPCtrl):
	__slots__ = ('backend', 'dialect', 'loop', 'counter_task', 'auth_sent', 'bs', 'cs')
	
	backend: Backend
	dialect: int
	loop: asyncio.AbstractEventLoop
	counter_task: Optional[VoidTaskType]
	auth_sent: bool
	bs: Optional[BackendSession]
	cs: Optional[ChatSession]
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.loop = backend.loop
		self.counter_task = None
		self.auth_sent = False
		self.bs = None
		self.cs = None
	
	def on_connect(self) -> None:
		self.counter_task = self.loop.create_task(self._conn_auth_limit_counter())
	
	def _on_close(self) -> None:
		if self.counter_task is not None:
			try:
				self.counter_task.cancel()
			except:
				pass
			self.counter_task = None
		if self.cs:
			self.cs.close()
	
	# State = Auth
	
	def _m_usr(self, trid: Optional[str], arg: Optional[str], token: Optional[str], *args: Any) -> None:
		#>>> USR trid email@example.com token (MSNP < 16)
		#>>> USR trid email@example.com;{00000000-0000-0000-0000-000000000000} token (MSNP >= 16)
		self.auth_sent = True
		if trid is None or arg is None or token is None or len(args) > 0:
			self.close()
			return
		
		(email, pop_id) = decode_email_pop(arg)
		
		data = self.backend.auth_service.pop_token('sb/xfr', token) # type: Optional[Tuple[BackendSession, int]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		bs, dialect = data
		bs_pop_id = bs.front_data.get('msn_pop_id') or ''
		if bs.user.email != email or (dialect >= 16 and pop_id is not None and bs_pop_id.lower() != normalize_pop_id(pop_id).lower()):
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		chat = self.backend.chat_create()
		
		try:
			if pop_id is not None:
				pop_id = normalize_pop_id(pop_id)
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task is not None and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		self.send_reply('USR', trid, 'OK', arg, cs.user.status.name or cs.user.email)
	
	def _m_ans(self, trid: Optional[str], arg: Optional[str], token: Optional[str], sessid: Optional[int], *args: Any) -> None:
		#>>> ANS trid email@example.com token sessionid (MSNP < 16)
		#>>> ANS trid email@example.com;{00000000-0000-0000-0000-000000000000} token sessionid (MSNP >= 16)
		self.auth_sent = True
		if trid is None or arg is None or token is None or sessid is None or len(args) > 0:
			self.close()
			return
		
		(email, pop_id) = decode_email_pop(arg)
		
		data = self.backend.auth_service.get_token('sb/cal', token) # type: Optional[Tuple[BackendSession, int, Chat]]
		if data is None:
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		expiry = self.backend.auth_service.get_token_expiry('sb/cal', token) or 0
		self.backend.auth_service.pop_token('sb/cal', token)
		if round(time.time() - expiry) >= 60:
			self.close()
			return
		
		(bs, dialect, chat) = data
		bs_pop_id = bs.front_data.get('msn_pop_id') or ''
		if bs.user.email != email or (dialect >= 16 and pop_id is not None and bs_pop_id.lower() != normalize_pop_id(pop_id).lower()):
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		if chat is None or sessid != chat.ids.get('main'):
			self.close()
			return
		
		try:
			if pop_id is not None:
				pop_id = normalize_pop_id(pop_id)
			cs = chat.join('msn', bs, ChatEventHandler(self), pop_id = pop_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, dialect), trid)
			return
		self.dialect = dialect
		self.bs = bs
		self.cs = cs
		if self.counter_task and not self.counter_task.cancelled():
			self.counter_task.cancel()
			self.counter_task = None
		
		roster_chatsessions = list(chat.get_roster_single()) # type: List[ChatSession]
		
		if dialect >= 16:
			l = 0
			tmp = [] # type: List[ChatSession]
			seen_cses = set() # type: Set[ChatSession]
			for other_cs_primary in roster_chatsessions:
				if other_cs_primary in seen_cses or other_cs_primary is self.cs: continue
				for other_cs in chat.get_roster():
					if other_cs in seen_cses: continue
					if other_cs.user.email == other_cs_primary.user.email and not other_cs.primary_pop:
						seen_cses.add(other_cs)
						tmp.append(other_cs)
						l += 1
				seen_cses.add(other_cs_primary)
				tmp.append(other_cs_primary)
				if other_cs_primary.bs.front_data.get('msn_pop_id') is not None:
					l += 2
				else:
					l += 1
			i = 1
			for other_cs in tmp:
				other_user = other_cs.user
				capabilities = encode_capabilities_capabilitiesex(
					((other_cs.bs.front_data.get('msn_capabilities') or 0) if other_cs.bs.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC),
					other_cs.bs.front_data.get('msn_capabilitiesex') or 0,
				)
				self.send_reply(
					'IRO', trid, i, l, encode_email_pop(other_user.email, other_cs.bs.front_data.get('msn_pop_id')),
					other_user.status.name, capabilities,
				)
				if other_cs.primary_pop and other_cs.bs.front_data.get('msn_pop_id') is not None:
					i += 1
					self.send_reply('IRO', trid, i, l, other_user.email, other_user.status.name, capabilities)
				i += 1
		else:
			roster_one_per_user = [] # type: List[ChatSession]
			seen_users = { self.cs.user } # type: Set[User]
			for other_cs in roster_chatsessions:
				if other_cs.user in seen_users:
					continue
				roster_one_per_user.append(other_cs)
			l = len(roster_one_per_user)
			for i, other_cs in enumerate(roster_one_per_user):
				other_user = other_cs.user
				extra = () # type: Tuple[Any, ...]
				if dialect >= 12:
					# Capability flags in IRO were technically introduced by MSNP13, but there are MSNP12 logs that show that they
					# had been introduced in that protocol version by then
					extra = (
						(
							(other_cs.bs.front_data.get('msn_capabilities') or 0)
							if other_cs.bs.front_data.get('msn') is True
							else MAX_CAPABILITIES_BASIC
						),
					)
				self.send_reply('IRO', trid, i + 1, l, other_user.email, other_user.status.name, *extra)
		
		self.send_reply('ANS', trid, 'OK')
		
		chat.send_participant_joined(cs)
	
	# State = Live
	
	def _m_cal(self, trid: str, invitee_email: str) -> None:
		#>>> CAL trid email@example.com
		cs = self.cs
		assert cs is not None
		
		bs = self.bs
		assert bs is not None
		
		if '@' not in invitee_email:
			self.send_reply(Err.InvalidUser2, trid)
			return
		
		invitee_uuid = self.backend.util_get_uuid_from_email(invitee_email)
		if invitee_uuid is None:
			self.send_reply(Err.PrincipalNotOnline, trid)
			return
		
		chat = cs.chat
		try:
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			invitee = self.backend._load_user_record(invitee_uuid)
			if invitee is None:
				return
			if invitee_email != bs.user.email:
				ctc = detail.contacts.get(invitee_uuid)
				if ctc is not None:
					if ctc.status.is_offlineish():
						raise error.ContactNotOnline()
				else:
					if invitee.status.is_offlineish():
						raise error.ContactNotOnline()
			
			cs.invite(invitee)
		except Exception as ex:
			# WLM 2009 sends a `CAL` with the invitee being the owner when a SB session is first initiated. If there are no other
			# PoPs of the owner, send a `JOI` for now to fool the client.
			chat_roster_single = list(chat.get_roster_single())
			if (
				isinstance(ex, error.ContactAlreadyOnList) and invitee_email == bs.user.email
				and len(chat_roster_single) == 1 and chat_roster_single[0] is cs and self.dialect >= 16
			):
				self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
				cs.evt.on_participant_joined(cs, True, False)
				return
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
		else:
			self.send_reply('CAL', trid, 'RINGING', chat.ids['main'])
			if self.dialect >= 16 and invitee_email == bs.user.email:
				cs.evt.on_participant_joined(cs, True, False)
	
	def _m_msg(self, trid: str, ack: str, data: bytes) -> None:
		#>>> MSG trid [UNAD] len
		bs = self.bs
		assert bs is not None
		cs = self.cs
		assert cs is not None
		
		if ack not in ('U','N','A','D') or len(data) > 1664:
			self.close()
			return
		
		try:
			cs.send_message_to_everyone(messagedata_from_msnp(cs.user, bs.front_data.get('msn_pop_id'), ack, data))
		except error.SpecialMessageNotSentWithDType:
			self.close()
			return
		
		# TODO: Implement ACK/NAK
		if ack == 'U':
			return
		any_failed = False
		if any_failed: # ADN
			self.send_reply('NAK', trid)
		elif ack != 'N': # AD
			self.send_reply('ACK', trid)
	
	async def _conn_auth_limit_counter(self) -> None:
		counter = 0
		
		while counter < 1:
			await asyncio.sleep(60)
			counter += 1
		
		if counter == 1:
			if not self.auth_sent:
				self.close()

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl',)
	
	ctrl: MSNPCtrlSB
	
	def __init__(self, ctrl: MSNPCtrlSB) -> None:
		self.ctrl = ctrl
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		cs = self.cs
		
		if (not first_pop or cs_other.user is cs.user) and ctrl.dialect < 16: return
		
		user = cs_other.user
		
		pop_id_other = cs_other.bs.front_data.get('msn_pop_id')
		if (
			(
				pop_id_other is not None
				and (pop_id_other != cs.bs.front_data.get('msn_pop_id') or cs_other.user is not cs.user)
			)
			and ctrl.dialect >= 16
		):
			email = '{};{}'.format(user.email, '{' + pop_id_other + '}')
		else:
			email = user.email
		
		# Capability flags in JOI were technically introduced by MSNP13, but there are MSNP12 logs that show that they
		# had been introduced in that protocol version by then
		if 12 <= ctrl.dialect <= 15:
			extra = (
				(
					(cs_other.bs.front_data.get('msn_capabilities') or 0)
					if cs_other.bs.front_data.get('msn') is True
					else MAX_CAPABILITIES_BASIC
				),
			) # type: Tuple[Any, ...]
		elif ctrl.dialect >= 16:
			extra = (
				encode_capabilities_capabilitiesex(
					(
						(cs_other.bs.front_data.get('msn_capabilities') or 0)
						if cs_other.bs.front_data.get('msn') is True
						else MAX_CAPABILITIES_BASIC
					),
					cs_other.bs.front_data.get('msn_capabilitiesex') or 0,
				),
			)
		else:
			extra = ()
		ctrl.send_reply('JOI', email, user.status.name, *extra)
		if cs_other.user is not cs.user and pop_id_other is not None and first_pop and ctrl.dialect >= 16:
			ctrl.send_reply('JOI', user.email, user.status.name, *extra)
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		ctrl = self.ctrl
		if not last_pop and ctrl.dialect < 16: return
		pop_id_other = cs_other.bs.front_data.get('msn_pop_id')
		if pop_id_other is not None and ctrl.dialect >= 16:
			email = '{};{}'.format(cs_other.user.email, '{' + pop_id_other + '}')
		else:
			email = cs_other.user.email
		self.ctrl.send_reply('BYE', email)
		if last_pop and pop_id_other is not None and ctrl.dialect >= 16:
			self.ctrl.send_reply('BYE', cs_other.user.email)
	
	def on_chat_invite_declined(
		self, chat: Chat, invitee: User, *, invitee_id: Optional[str] = None, message: Optional[str] = None, group_chat: bool = False,
	) -> None:
		pass
	
	def on_chat_updated(self) -> None:
		pass
	
	def on_chat_roster_updated(self) -> None:
		pass
	
	def on_participant_status_updated(self, cs_other: ChatSession, first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		if data.type is not MessageType.TypingDone:
			self.ctrl.send_reply('MSG', data.sender.email, data.sender.status.name, messagedata_to_msnp(data))
	
	def on_close(self) -> None:
		self.ctrl.close()

def messagedata_from_msnp(sender: User, sender_pop_id: Optional[str], ack: str, data: bytes) -> MessageData:
	# TODO: Implement these `Content-Type`s:
	# voice:
	# b'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgsinvite; charset=UTF-8\r\n\r\nInvitation-Command: CANCEL\r\n
	# Cancel-Code: TIMEOUT\r\nInvitation-Cookie: 126868552\r\nSession-ID: {CE64F989-2AAD-44C4-A780-2C55A812B0B6}\r\n
	# Conn-Type: Firewall\r\nSip-Capability: 1\r\n\r\n'
	# xfer:
	# 	b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Gt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\xb2\x04\x00
	# 	\x00\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00INVITE MSNMSGR:t2h@hotmail.com MSNSLP/1.0\r\n
	# 	To: <msnmsgr:t2h@hotmail.com>\r\nFrom: <msnmsgr:t1h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;
	# 	branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 0 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\n
	# 	Max-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 948\r\n\r\n
	# 	EUF-GUID: {5D3E02AB-6190-11D3-BBBB-00C04F795683}\r\nSessionID: 180646677\r\nAppID: 2\r\n
	# 	Context: fgIAAAMAAAAAAAAAAAAAAAEAAABhAC4AdAB4AHQAA...AAAAAAAAA/////wAAAAAAAAAAAAAAAAAAA\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Gt\xc4\n\xb2\x04\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00H\x00\x00\x00
	# 	\x00\x00\x00\x00wn\xc5\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
	# 	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Wt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
	# 	\x02\x00\x00\x00Gt\xc4\nwn\xc5\n\xfa\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# xfer decline:
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t1h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Xt\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00
	# 	\x00\x00\x00N\x0b\xc7\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00MSNSLP/1.0 603 Decline\r\n
	# 	To: <msnmsgr:t1h@hotmail.com>\r\nFrom: <msnmsgr:t2h@hotmail.com>\r\nVia: MSNSLP/1.0/TLP ;
	# 	branch={CDE28DAF-B67C-4B2D-8186-D3F46EEF0916}\r\nCSeq: 1 \r\nCall-ID: {F87327A8-741F-4FEF-AB63-45D06F51A0C2}\r\n
	# 	Max-Forwards: 0\r\nContent-Type: application/x-msnmsgr-sessionreqbody\r\nContent-Length: 25\r\n\r\n
	# 	SessionID: 180646677\r\n\r\n\x00\x00\x00\x00\x00'
	# b'MIME-Version: 1.0\r\nContent-Type: application/x-msnmsgrp2p\r\nP2P-Dest: t2h@hotmail.com\r\n\r\n
	# 	\x00\x00\x00\x00Ht\xc4\n\x00\x00\x00\x00\x00\x00\x00\x00K\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
	# 	\x02\x00\x00\x00Xt\xc4\nN\x0b\xc7\nK\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	# etc.
	
	try:
		i = data.index(b'\r\n\r\n') + 4
		headers = Parser().parsestr(data[:i].decode('utf-8'))
		body_raw = data[i:]
	except:
		type = MessageType.Chat
		text = "(Unsupported MSNP Content-Type)"
	
	content_type = headers.get_content_type()
	if content_type is not None:
		if content_type == 'text/x-msmsgscontrol':
			type = MessageType.Typing
			text = ''
		elif content_type == 'text/x-msnmsgr-datacast':
			body = body_raw.decode('utf-8')
			id_start = body.index('ID:') + 3
			id_end = body.index('\r\n', id_start)
			id = body[id_start:id_end].strip()
			if id is '1':
				type = MessageType.Nudge
				text = ''
			else:
				type = MessageType.Chat
				text = "(Unsupported MSNP Content-Type)"
		elif content_type == 'application/x-msnmsgrp2p':
			if ack != 'D':
				raise error.SpecialMessageNotSentWithDType()
			type = MessageType.Chat
			text = "(Unsupported MSNP Content-Type)"
		elif content_type == 'text/plain':
			type = MessageType.Chat
			text = body_raw.decode('utf-8')
		else:
			type = MessageType.Chat
			text = "(Unsupported MSNP Content-Type)"
	else:
		type = MessageType.Chat
		text = "(Unsupported MSNP Content-Type)"
	
	message = MessageData(sender = sender, sender_pop_id = sender_pop_id, type = type, text = text)
	message.front_cache['msnp'] = data
	return message

def messagedata_to_msnp(data: MessageData) -> bytes:
	if 'msnp' not in data.front_cache:
		if data.type is MessageType.Typing:
			s = F'MIME-Version: 1.0\r\nContent-Type: text/x-msmsgscontrol\r\nTypingUser: {data.sender.email}\r\n\r\n\r\n'
		elif data.type is MessageType.Nudge:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: 1\r\n\r\n'
		elif data.type is MessageType.Chat:
			s = 'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n' + (data.text or '')
		else:
			raise ValueError("unknown message type", data.type)
		data.front_cache['msnp'] = s.encode('utf-8')
	return data.front_cache['msnp']
