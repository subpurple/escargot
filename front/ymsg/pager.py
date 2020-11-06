from typing import Optional, Dict, Any, Tuple
import secrets
import datetime
import asyncio
import time
import binascii
import struct

from util.misc import Logger, gen_uuid, MultiDict, arbitrary_decode, arbitrary_encode

import settings
from core import event, error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import (
	Substatus, Lst, User, UserDetail, Contact, GroupChat, GroupChatRole, TextWithData,
	MessageData, MessageType, UserStatus, LoginOption, OIM,
)
from core.client import Client
from core.auth import AuthService, GenTokenStr

from .ymsg_ctrl import YMSGCtrlBase
from .misc import YMSGService, YMSGStatus, split_to_chunks
from . import misc, Y64

# "Pre" because it's needed before BackendSession is created.
# Comment out session ID stuff as that'll have to be reworked with account usernames being a thing
#PRE_SESSION_ID: Dict[str, int] = {}

class YMSGCtrlPager(YMSGCtrlBase):
	__slots__ = ('backend', 'dialect', 'sess_id', 'challenge', 't_cookie_token', 'bs', 'client')
	
	backend: Backend
	dialect: int
	sess_id: int
	challenge: Optional[bytes]
	t_cookie_token: Optional[str]
	bs: Optional[BackendSession]
	client: Client
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.sess_id = 0
		self.challenge = None
		self.t_cookie_token = None
		self.bs = None
		self.client = Client('yahoo', '?', via)
	
	def _on_close(self, remove_sess_id: bool = True) -> None:
		if self.bs:
			#self.bs.close(sess_id = PRE_SESSION_ID.get(self.bs.user.username))
			#if remove_sess_id:
			#	PRE_SESSION_ID.pop(self.yahoo_id, None)
			self.bs.close()
	
	# State = Auth
	
	def _y_004c(self, *args: Any) -> None:
		# SERVICE_HANDSHAKE (0x4c); acknowledgement of the server
		
		self.client = Client('yahoo', 'YMSG{}'.format(str(args[0])), self.client.via)
		self.dialect = int(args[0])
		self.send_reply(YMSGService.Handshake, YMSGStatus.BRB, 0, None)
	
	def _y_0057(self, *args: Any) -> None:
		# SERVICE_AUTH (0x57); send a challenge string for the client to craft two response strings with
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = yahoo_data.get(b'1')
		assert isinstance(yahoo_id, bytes)
		
		#self.sess_id = secrets.randbelow(4294967294) + 1
		#PRE_SESSION_ID[self.yahoo_id] = self.sess_id
		
		auth_dict = MultiDict([
			(b'1', yahoo_id),
		]) # type: MultiDict[bytes, bytes]
		
		if self.dialect == 9:
			self.challenge = generate_challenge_v1()
			auth_dict.add(b'94', self.challenge)
		elif self.dialect >= 10:
			# Implement V2 challenge string generation later
			# YMSG10 apparently supported the v2 challenge response too, use YMSG9 auth for that protocol for now
			if self.dialect == 10:
				self.challenge = generate_challenge_v1()
			auth_dict.add(b'94', self.challenge or b'')
			if self.dialect >= 11:
				auth_dict.add(b'13', b'1')
		
		self.send_reply(YMSGService.Auth, YMSGStatus.BRB, self.sess_id, auth_dict)
	
	def _y_0054(self, *args: Any) -> None:
		# SERVICE_AUTHRESP (0x54); verify response strings for successful authentication
		backend = self.backend
		
		y = None
		t = None
		authresp_error = None
		
		status = args[2]
		if status is YMSGStatus.WebLogin:
			status = YMSGStatus.Available
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = args[4].get(b'0') or b''
		active_yid = yahoo_data.get(b'1') or b''
		resp_6 = yahoo_data.get(b'6')
		resp_96 = yahoo_data.get(b'96')
		
		if b'' in (active_yid,yahoo_id):
			authresp_error = int(YMSGStatus.NotAtHome)
		
		yahoo_id_str = arbitrary_decode(yahoo_id)
		
		uuid = backend.util_get_uuid_from_username(yahoo_id_str)
		if uuid is None:
			authresp_error = int(YMSGStatus.NotAtHome)
		
		version = arbitrary_decode(yahoo_data.get(b'135') or b'') or 'unknown'
		self.client = Client('yahoo', version, self.client.via)
		
		# TODO: Dialect 11 not supported yet?
		assert 9 <= self.dialect <= 10
		
		assert self.challenge is not None
		if authresp_error is None:
			is_resp_correct = self._verify_challenge_v1(arbitrary_decode(yahoo_id), resp_6, resp_96)
			if is_resp_correct:
				# NOTE: Yahoo! Messenger *can* specify the `Y` and `T` cookies in this packet after multiple logins as long as it isn't
				# terminated. Verify and store cookies if needed.
				
				if b'59' in yahoo_data:
					tpl = list(yahoo_data.getall(b'59') or [])
					if len(tpl) != 2:
						self.send_reply(YMSGService.LogOff, YMSGStatus.Available, self.sess_id, None)
						self.close()
						return
					y = arbitrary_decode(tpl[0])
					t = arbitrary_decode(tpl[1])
				assert uuid is not None
				bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option = LoginOption.BootOthers)
				if bs is None:
					authresp_error = int(YMSGStatus.Bad)
				else:
					self.bs = bs
					self._util_authresp_final(status, cached_y = y, cached_t = t)
			else:
				authresp_error = int(YMSGStatus.Bad)
		
		if authresp_error is not None:
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, self.sess_id, MultiDict([
				(b'1', active_yid),
				(b'66', str(authresp_error).encode('utf-8')),
				(b'0', yahoo_id),
			]))
			self.close()
	
	def _util_authresp_final(self, status: YMSGStatus, *, cached_y: Optional[str] = None, cached_t: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		self.t_cookie_token = (cached_t[4:24] if cached_y and cached_t else GenTokenStr())
		
		bs.front_data['ymsg'] = True
		bs.front_data['ymsg_private_chats'] = {}
		bs.front_data['ymsg_chat_sessions'] = {}
		
		self._update_buddy_list(cached_y = cached_y, cached_t = cached_t, on_login = True)
		
		if self.dialect >= 10:
			kvs = MultiDict([
				(b'143', b'60'),
				(b'144', b'13')
			]) # type: MultiDict[bytes, bytes]
			self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, kvs)
		
		self._get_oims(user)
		
		if self.backend.notify_maintenance:
			bs.evt.on_system_message(None, self.backend.maintenance_mins)
	
	# State = Live
	
	def _y_0004(self, *args: Any) -> None:
		# SERVICE_ISBACK (0x04); notify contacts of online presence
		
		bs = self.bs
		assert bs is not None
		
		new_status = YMSGStatus(int(args[2]))
		
		me_status_update(bs, new_status)
	
	def _y_0003(self, *args: Any) -> None:
		# SERVICE_ISAWAY (0x03); notify contacts of FYI idle presence
		
		bs = self.bs
		assert bs is not None
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		new_status = YMSGStatus(int(yahoo_data.get(b'10') or b''))
		message = arbitrary_decode(yahoo_data.get(b'19') or b'')
		is_away_message = (yahoo_data.get(b'47') == b'1')
		me_status_update(bs, new_status, message = message, is_away_message = is_away_message)
	
	def _y_0012(self, *args: Any) -> None:
		# SERVICE_PINGCONFIGURATION (0x12); set the "ticks" and "tocks" of a ping sent
		
		kvs = MultiDict([
			(b'143', b'60'),
			(b'144', b'13')
		]) # type: MultiDict[bytes, bytes]
		self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, kvs)
	
	def _y_0016(self, *args: Any) -> None:
		# SERVICE_CLIENTHOSTSTATS (0x16); collects OS version, processor, and time zone
		#
		# 1: YahooId
		# 25: unknown ('C=0[0x01]F=1,P=0,C=0,H=0,W=0,B=0,O=0,G=0[0x01]M=0,P=0,C=0,S=0,L=3,D=1,N=0,G=0,F=0,T=0')
		# 146: Base64-encoded string of host OS (e.g.: 'V2luZG93cyAyMDAwLCBTZXJ2aWNlIFBhY2sgNA==' = 'Windows 2000, Service Pack 4')
		# 145: Base64-encoded string of processor type (e.g.: 'SW50ZWwgUGVudGl1bSBQcm8gb3IgUGVudGl1bQ==' = 'Intel Pentium Pro or Pentium')
		# 147: Base64-encoded string of time zone (e.g.: 'RWFzdGVybiBTdGFuZGFyZCBUaW1l' = 'Eastern Standard Time')
		
		return
	
	def _y_0015(self, *args: Any) -> None:
		# SERVICE_SKINNAME (0x15); used for IMVironments
		# Also happens when enabling/disabling Yahoo Helper.
		return
	
	def _y_0083(self, *args: Any) -> None:
		# SERVICE_FRIENDADD (0x83); add a friend to your contact list
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_yahoo_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		message = arbitrary_decode(yahoo_data.get(b'14') or b'')
		buddy_group = arbitrary_decode(yahoo_data.get(b'65') or b'')
		utf8 = arbitrary_decode(yahoo_data.get(b'97') or b'')
		
		group = None
		old_lists = None
		action_group_refresh = False
		
		add_request_response = MultiDict([
			(b'1', arbitrary_encode(yahoo_id)),
			(b'7', arbitrary_encode(contact_yahoo_id)),
			(b'65', arbitrary_encode(buddy_group))
		]) # type: MultiDict[bytes, bytes]
		
		# Yahoo! Messenger has a function that lets you add people by email address (a.k.a. stripping the "@domain.tld" part of the address and
		# filling that out in the "Yahoo! ID" section of the contact add dialog). Treat as is.
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id)
		if contact_uuid is None:
			add_request_response.add(b'66', b'3') # User doesn't exist in database
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		contact = contacts.get(contact_uuid)
		if contact is not None:
			old_lists = contact.lists
			if contact.lists & Lst.FL:
				if contact._groups:
					for group_other in contact._groups.copy():
						if detail._groups_by_id[group_other.id].name == buddy_group:
							add_request_response.add(b'66', b'2') # Contact already in group
							self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
							return
				else:
					if buddy_group == '(No Group)':
						add_request_response.add(b'66', b'2')
						self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
						return
		
		if buddy_group != '(No Group)':
			for grp in detail._groups_by_id.values():
				if grp.name == buddy_group:
					group = grp
					break
			
			if group is None:
				group = bs.me_group_add(buddy_group)
		
		ctc_head = self.backend._load_user_record(contact_uuid)
		assert ctc_head is not None
		
		try:
			contact_new = bs.me_contact_add(
				ctc_head.uuid, Lst.FL | Lst.AL, message = (TextWithData(message, utf8) if message is not None else None),
				adder_id = yahoo_id, needs_notify = True,
			)[0]
		except error.ListIsFull:
			add_request_response.add(b'66', b'6') # Contact list full
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		except:
			add_request_response.add(b'66', b'1') # General failure
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		
		if (contact_new is not None and contact is None) or (old_lists is not None and (not old_lists & Lst.FL and not old_lists & Lst.BL)):
			contact_struct = MultiDict([
				(b'8', (b'1' if not contact_new.status.is_offlineish() else b'0')),
			]) # type: MultiDict[bytes, bytes]
			add_contact_status_to_data(contact_struct, ctc_head.status, ctc_head)
			
			self.send_reply(YMSGService.ContactNew, YMSGStatus.BRB, self.sess_id, contact_struct)
			
		add_request_response.add(b'66', b'0') # Success
		self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
		try:
			# TODO: Moving/copying contacts to groups
			if len(contact_new._groups) >= 1 or (contact_new._groups and buddy_group == '(No Group)'): action_group_refresh = True
			if buddy_group == '(No Group)':
				for group_other in contact_new._groups.copy():
					group_full = False
					bs.me_group_contact_remove(group_other.id, contact_new.head.uuid)
					for ctc_other in detail.contacts.values():
						if ctc_other is contact_new: continue
						for group_ctc in ctc_other._groups.copy():
							if group_ctc.id is group_other.id:
								group_full = True
								break
						if group_full:
							break
			if group is not None:
				bs.me_group_contact_add(group.id, contact_new.head.uuid)
			
			if action_group_refresh: self._update_buddy_list()
		except error.ContactAlreadyOnList:
			# Ignore, because this condition was checked earlier, so the only way this
			# can happen is if the the contact list gets in an inconsistent state.
			# (I.e. contact is not on FL, but still part of groups.)
			pass
	
	def _y_0086(self, *args: Any) -> None:
		# SERVICE_CONTACTDENY (0x86); deny a contact request
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		adder_to_deny = arbitrary_decode(yahoo_data.get(b'7') or b'')
		deny_message = arbitrary_decode(yahoo_data.get(b'14') or b'')
		
		adder_uuid = backend.util_get_uuid_from_username(adder_to_deny)
		assert adder_uuid is not None
		bs = self.bs
		assert bs is not None
		bs.me_contact_deny(adder_uuid, deny_message, addee_id = yahoo_id)
	
	def _y_0089(self, *args: Any) -> None:
		# SERVICE_GROUPRENAME (0x89); rename a contact group
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		group_name = arbitrary_decode(yahoo_data.get(b'65') or b'')
		new_group_name = arbitrary_decode(yahoo_data.get(b'67') or b'')
		bs = self.bs
		assert bs is not None
		
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		group = None
		
		# "(No Group)" is used for displaying group-less contacts; ignore any requests to rename the "group"
		
		if '(No Group)' not in (group_name,new_group_name):
			for grp in detail._groups_by_id.values():
				if grp.name == group_name:
					group = grp
			
			if group is not None:
				try:
					bs.me_group_edit(group.id, new_name = new_group_name)
				except:
					pass
			
			group_rename_response = MultiDict([
				(b'1', arbitrary_encode(yahoo_id or '')),
				(b'66', b'0'),
				(b'67', arbitrary_encode(new_group_name or '')),
				(b'65', arbitrary_encode(group_name or '')),
			]) # type: MultiDict[bytes, bytes]
			
			self.send_reply(YMSGService.GroupRename, YMSGStatus.BRB, self.sess_id, group_rename_response)
		
		self._update_buddy_list()
	
	def _y_0084(self, *args: Any) -> None:
		# SERVICE_FRIENDREMOVE (0x84); remove a buddy from your list
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		buddy_group = arbitrary_decode(yahoo_data.get(b'65') or b'')
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		group = None
		
		contact_uuid = backend.util_get_uuid_from_username(contact_id)
		if contact_uuid is None:
			return
		
		contact = detail.contacts.get(contact_uuid)
		
		if contact is None:
			return
		
		if contact._groups:
			for group_other in contact._groups.copy():
				if detail._groups_by_id[group_other.id].name == buddy_group:
					group = detail._groups_by_id[group_other.id]
					break
		
		if group is None and buddy_group != '(No Group)':
			return
		
		if group is not None:
			bs.me_group_contact_remove(group.id, contact.head.uuid)
		
		if not contact._groups:
			bs.me_contact_remove(contact_uuid, Lst.FL)
		
		remove_buddy_response = MultiDict([
			(b'1', arbitrary_encode(yahoo_id)),
			(b'66', b'0'),
			(b'7', arbitrary_encode(contact_id)),
			(b'65', arbitrary_encode(buddy_group)),
		]) # type: MultiDict[bytes, bytes]
		
		self.send_reply(YMSGService.FriendRemove, YMSGStatus.BRB, self.sess_id, remove_buddy_response)
		
		self._update_buddy_list()
	
	def _y_0085(self, *args: Any) -> None:
		# SERVICE_IGNORE (0x85); add/remove someone from your ignore list
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		ignored_yahoo_id = arbitrary_decode(yahoo_data.get(b'7') or b'')
		ignore_mode = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		ignore_reply_response = MultiDict([
			(b'0', arbitrary_encode(yahoo_id)),
			(b'7', arbitrary_encode(ignored_yahoo_id)),
			(b'13', arbitrary_encode(ignore_mode))
		])
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		contacts = detail.contacts
		
		ignored_uuid = backend.util_get_uuid_from_username(ignored_yahoo_id)
		if ignored_uuid is None:
			ignore_reply_response.add(b'66', b'3')
			self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
			return
		
		if int(ignore_mode) == 1:
			contact = contacts.get(ignored_uuid)
			if contact is not None:
				if contact.lists & Lst.BL:
					ignore_reply_response.add(b'66', b'2')
					self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
					return
			
			bs.me_contact_add(ignored_uuid, Lst.BL, name = ignored_yahoo_id)
		elif int(ignore_mode) == 2:
			bs.me_contact_remove(ignored_uuid, Lst.BL)
		else:
			return
		
		self.send_reply(YMSGService.AddIgnore, YMSGStatus.BRB, self.sess_id, None)
		ignore_reply_response.add(b'66', b'0')
		self._update_buddy_list()
		self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
	
	def _y_000a(self, *args: Any) -> None:
		# SERVICE_USERSTAT (0x0a); synchronize logged on user's status
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		self.send_reply(
			YMSGService.UserStat, bs.front_data.get('ymsg_status') or YMSGStatus.FromSubstatus(user.status.substatus),
			self.sess_id, self._gen_multi_user_status_dict(user),
		)
	
	def _y_0055(self, *args: Any) -> None:
		# SERVICE_LIST (0x55); send a user's buddy list
		
		self._update_buddy_list(after_login = True)
	
	def _y_008a(self, *args: Any) -> None:
		# SERVICE_PING (0x8a); send a response ping after the client pings
		bs = self.bs
		assert bs is not None
		self.send_reply(YMSGService.Ping, YMSGStatus.Available, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(bs.user.username)),
		]))
	
	def _y_0008(self, *args: Any) -> None:
		# SERVICE_IDDEACTIVATE (0x08); deactivate an alias
		
		return
	
	def _y_0007(self, *args: Any) -> None:
		# SERVICE_IDACTIVATE (0x07); activate an alias
		
		return
	
	def _y_004f(self, *args: Any) -> None:
		# SERVICE_PEERTOPEER (0x4f); see if P2P messaging is possible. Possibly also used for other P2P actions
		
		backend = self.backend
		# Formality; make sure unregistered sessions aren't able to send these packets
		bs = self.bs
		assert bs is not None
		
		yahoo_data = args[4]
		recipient_uuid = backend.util_get_uuid_from_username(arbitrary_decode(yahoo_data.get(b'5')))
		if recipient_uuid is None:
			return
		recipient_head = backend._load_user_record(recipient_uuid)
		if recipient_head is None:
			return
		
		for bs_other in backend.util_get_sessions_by_user(recipient_head):
			bs_other.evt.ymsg_on_p2p_msg_request(self.sess_id, yahoo_data)
	
	def _y_004b(self, *args: Any) -> None:
		# SERVICE_NOTIFY (0x4b); notify a contact of an action (typing, games, etc.)
		backend = self.backend
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		notify_type = yahoo_data.get(b'49') # typing, games, etc.
		typing_flag = yahoo_data.get(b'13')
		if typing_flag is not None:
			typing_flag = arbitrary_decode(typing_flag)
		contact_yahoo_id = yahoo_data.get(b'5')
		if contact_yahoo_id is not None:
			contact_yahoo_id = arbitrary_decode(contact_yahoo_id)
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id)
		if contact_uuid is None:
			return
		
		try:
			cs, _ = self._get_private_chat_with(contact_uuid)
			if cs is not None:
				cs.preferred_name = yahoo_id
				cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data, notify_type = notify_type, typing_flag = typing_flag))
		except error.ContactNotOnline:
			pass
	
	def _y_0006(self, *args: Any) -> None:
		# SERVICE_MESSAGE (0x06); send a message to a user
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		contact_yahoo_id = arbitrary_decode(yahoo_data.get(b'5') or b'')
		
		self._message_common(yahoo_data, contact_yahoo_id)
	
	def _y_0017(self, *args: Any) -> None:
		# SERVICE_MASSMESSAGE (0x17); send a message to multiple users
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#yahoo_id = yahoo_data.get(b'1')
		
		contact_yahoo_ids = [
			arbitrary_decode(contact_yahoo_id)
			for contact_yahoo_id in (yahoo_data.getall(b'5') or [])
		]
		for contact_yahoo_id in contact_yahoo_ids:
			self._message_common(yahoo_data, contact_yahoo_id)
	
	def _y_0050(self, *args: Any) -> None:
		# SERVICE_VIDEOCHAT (0x50); create a webcam token for authentication
		#bs = self.bs
		#assert bs is not None
		#
		#yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		#if not yahoo_data.get(b'1'): return
		#
		#webcam_token = self.backend.auth_service.create_token('ymsg/webcam', yahoo_data.get(b'1'), lifetime = 86400)
		#
		#self.send_reply(YMSGService.VideoChat, YMSGStatus.BRB, self.sess_id, MultiDict([
		#	(b'1', yahoo_data.get(b'1')),
		#	(b'5', yahoo_data.get(b'1')),
		#	(b'61', webcam_token),
		#]))
		
		return
	
	def _y_004d(self, *args: Any) -> None:
		# SERVICE_P2PFILEXFER (0x4d); initiate P2P file transfer. Due to this service being present
		# in 3rd-party libraries; we can implement it here
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		
		contact_id = arbitrary_decode(yahoo_data.get(b'5') or b'')
		contact_uuid = backend.util_get_uuid_from_username(contact_id)
		if contact_uuid is None:
			return
		
		for bs_other in backend._sc.iter_sessions():
			if bs_other.user.uuid == contact_uuid:
				bs_other.evt.ymsg_on_xfer_init(self.sess_id, yahoo_data)
	
	def _y_0018(self, *args: Any) -> None:
		# SERVICE_CONFINVITE (0x18); send a conference invite to one or more people
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_roster = [
			arbitrary_decode(conf_member)
			for conf_member in (yahoo_data.getall(b'52') or [])
		]
		# Comma-separated yahoo ids
		conf_roster_2 = yahoo_data.get(b'51')
		if conf_roster_2 is not None:
			conf_roster.extend(arbitrary_decode(conf_roster_2).split(','))
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		invite_msg = arbitrary_decode(yahoo_data.get(b'58') or b'')
		voice_chat = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id, create = True)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_roster:
			conf_user_uuid = backend.util_get_uuid_from_username(conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_001c(self, *args: Any) -> None:
		# SERVICE_CONFADDINVITE (0x1c); send a conference invite to an existing conference to one or more people
		backend = self.backend
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_new_roster_str = yahoo_data.get(b'51')
		if conf_new_roster_str is None:
			return
		conf_new_roster = arbitrary_decode(conf_new_roster_str).split(',')
		#conf_roster = [
		#	arbitrary_decode(conf_member)
		#	for conf_member in (yahoo_data.getall(b'52') or yahoo_data.getall(b'53') or [])
		#]
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		if not conf_id:
			return
		invite_msg = arbitrary_decode(yahoo_data.get(b'58') or b'')
		voice_chat = arbitrary_decode(yahoo_data.get(b'13') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_new_roster:
			conf_user_uuid = backend.util_get_uuid_from_username(conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_0019(self, *args: Any) -> None:
		# SERVICE_CONFLOGON (0x19); request for me to join a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#inviter_ids = yahoo_data.getall(b'3')
		#if inviter_ids is None:
		#	return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		if not conf_id:
			return
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
	
	def _y_001a(self, *args: Any) -> None:
		# SERVICE_CONFDECLINE (0x1a); decline a request to join a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		
		bs = self.bs
		assert bs is not None
		
		inviter_ids = [
			arbitrary_decode(inviter_id).lower() for inviter_id in (yahoo_data.getall(b'3') or [])
		]
		if not inviter_ids:
			return
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		deny_msg = arbitrary_decode(yahoo_data.get(b'14') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		
		for cs in chat.get_roster():
			if cs.user.username.lower() not in inviter_ids:
				continue
			cs.evt.on_chat_invite_declined(chat, bs.user, invitee_id = yahoo_id, message = deny_msg)
	
	def _y_001d(self, *args: Any) -> None:
		# SERVICE_CONFMSG (0x1d); send a message in a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#conf_user_ids = yahoo_data.getall(b'53')
		#if conf_user_ids is None:
		#	return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		cs.preferred_name = yahoo_id
		cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data))
	
	def _y_001b(self, *args: Any) -> None:
		# SERVICE_CONFLOGOFF (0x1b); leave a conference
		
		yahoo_data = args[4] # type: MultiDict[bytes, bytes]
		
		#conf_roster = yahoo_data.getall(b'3')
		#if conf_roster is None:
		#	return
		
		yahoo_id = arbitrary_decode(yahoo_data.get(b'1') or b'')
		conf_id = arbitrary_decode(yahoo_data.get(b'57') or b'')
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		cs = self._get_chat_session(yahoo_id, chat)
		if cs is not None:
			cs.close()
	
	# Other functions
	
	def _message_common(self, yahoo_data: MultiDict[bytes, bytes], contact_yahoo_id: Optional[str]) -> None:
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if contact_yahoo_id is not None and contact_yahoo_id.lower() == 'yahoohelper':
			yhlper_msg_dict = MultiDict([
				(b'5', yahoo_data.get(b'1') or b''),
				(b'4', b'YahooHelper'),
				(b'14', YAHOO_HELPER_MSG.encode('utf-8')),
			]) # type: MultiDict[bytes, bytes]
			
			if yahoo_data.get(b'63') is not None:
				yhlper_msg_dict.add(b'63', yahoo_data.get(b'63') or b'')
			
			if yahoo_data.get(b'64') is not None:
				yhlper_msg_dict.add(b'64', yahoo_data.get(b'64') or b'')
			
			yhlper_msg_dict.add(b'97', b'1')
			
			self.send_reply(YMSGService.Message, YMSGStatus.BRB, self.sess_id, yhlper_msg_dict)
			return
		
		contact_uuid = backend.util_get_uuid_from_username(contact_yahoo_id or '')
		if contact_uuid is None:
			return
		
		try:
			cs, evt = self._get_private_chat_with(contact_uuid)
			if None not in (cs, evt):
				evt._send_when_user_joins(contact_uuid, messagedata_from_ymsg(cs.user, yahoo_data))
		except error.ContactNotOnline:
			contact_user = self.backend._load_user_record(contact_uuid)
			if contact_user is None:
				return
			contact_detail = self.backend._load_detail(contact_user)
			if contact_detail is None:
				return
			ctc_self = contact_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & Lst.BL:
					return
			elif ctc_self is None and contact_user.settings.get('BLP', 'AL') == 'BL':
				return
			md = messagedata_from_ymsg(contact_user, yahoo_data)
			if md.type is MessageType.Chat:
				(ip, _) = self.peername
				from_user_id = None
				
				key1_val = md.front_cache['ymsg'].get(b'1')
				if key1_val is not None:
					from_user_id = arbitrary_decode(key1_val)
				
				self.backend.user_service.save_oim(
					bs, contact_uuid, gen_uuid(), ip, md.text or '', False if md.front_cache['ymsg'].get(b'97') is b'0' else True,
					from_user_id = from_user_id,
				)
		except error.ContactNotOnList:
			pass
	
	def _get_private_chat_with(self, other_user_uuid: str) -> Tuple[ChatSession, 'ChatEventHandler']:
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		other_user = self.backend._load_user_record(other_user_uuid)
		if other_user is None:
			raise error.ContactNotOnList()
		other_user_ctc = detail.contacts.get(other_user.uuid)
		if other_user_ctc is not None and other_user_ctc.lists & Lst.BL:
			raise error.ContactNotOnList()
		if other_user_uuid not in bs.front_data['ymsg_private_chats'] and not other_user.status.is_offlineish():
			other_user_detail = self.backend._load_detail(other_user)
			if other_user_detail is None: raise error.ContactNotOnline()
			ctc_self = other_user_detail.contacts.get(user.uuid)
			if ctc_self is not None:
				if ctc_self.lists & Lst.BL: raise error.ContactNotOnline()
			chat = self.backend.chat_create()
			chat.front_data['ymsg_twoway_only'] = True
			
			# `user` joins
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt)
			bs.front_data['ymsg_private_chats'][other_user_uuid] = (cs, evt)
			cs.invite(other_user)
			self.backend.loop.create_task(self._check_private_chat(chat, other_user, bs))
		elif other_user.status.is_offlineish():
			raise error.ContactNotOnline()
		return bs.front_data['ymsg_private_chats'].get(other_user_uuid)
	
	def _get_chat_by_id(self, scope: str, id: str, *, create: bool = False) -> Optional[Chat]:
		chat = self.backend.chat_get(scope, id)
		if chat is None and create:
			chat = self.backend.chat_create()
			chat.add_id(scope, id)
		return chat
	
	def _get_chat_session(self, yahoo_id: Optional[str], chat: Chat, *, create: bool = False) -> Optional[ChatSession]:
		bs = self.bs
		assert bs is not None
		
		cs = bs.front_data['ymsg_chat_sessions'].get(chat)
		if cs is None and create:
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt, preferred_name = yahoo_id)
			bs.front_data['ymsg_chat_sessions'][chat] = cs
			chat.send_participant_joined(cs)
		return cs
	
	def _update_buddy_list(self, cached_y: Optional[str] = None, cached_t: Optional[str] = None, on_login: bool = False, after_login: bool = False) -> None:
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		cs = list(contacts.values())
		cs_fl = [c for c in cs if c.lists & Lst.FL and not c.lists & Lst.BL]
		
		contact_group_list = []
		for grp in detail._groups_by_id.values():
			contact_list = []
			for c in cs_fl:
				for group in c._groups.copy():
					if group.id == grp.id:
						contact_list.append(c.head.username)
			if contact_list:
				contact_group_list.append(grp.name + ':' + ','.join(contact_list) + '\n')
		# Handle contacts that aren't part of any groups
		contact_list = [c.head.username for c in cs_fl if not c._groups]
		if contact_list:
			contact_group_list.append('(No Group):' + ','.join(contact_list) + '\n')
		
		contact_list_format = ''.join(contact_group_list)
		
		ignore_list = [c.head.username for c in cs if c.lists & Lst.BL]
		ignore_list_format = ','.join(ignore_list)
		
		list_reply_kvs = MultiDict() # type: MultiDict[bytes, bytes]
		
		if len(contact_list_format) > 815:
			contact_chunks = split_to_chunks(contact_list_format, 815)
			for contact_chunk in contact_chunks:
				self.send_reply(YMSGService.List, YMSGStatus.NotInOffice, self.sess_id, MultiDict([
					(b'87', arbitrary_encode(contact_chunk)),
				]))
		else:
			list_reply_kvs.add(b'87', arbitrary_encode(contact_list_format))
		
		if len(ignore_list_format) > 815:
			ignore_chunks = split_to_chunks(ignore_list_format, 815)
			for ignore_chunk in ignore_chunks:
				self.send_reply(YMSGService.List, YMSGStatus.NotInOffice, self.sess_id, MultiDict([
					(b'88', ignore_chunk.encode('utf-8')),
				]))
		else:
			list_reply_kvs.add(b'88', ignore_list_format.encode('utf-8'))
		
		list_reply_kvs.add(b'89', arbitrary_encode(user.username))
		
		if (
			cached_y is not None and cached_t is not None
			and backend.auth_service.get_token('ymsg/cookie', cached_y)
			and backend.auth_service.get_token('ymsg/cookie', cached_t)
		):
			list_reply_kvs.add(b'59', arbitrary_encode(cached_y))
			list_reply_kvs.add(b'59', arbitrary_encode(cached_t))
		else:
			(y_cookie, t_cookie, y_expiry, t_expiry) = self._refresh_cookies()
			
			domain = ('yahooloopback.log1p.xyz' if settings.DEBUG else settings.TARGET_HOST)
			list_reply_kvs.add(b'59', arbitrary_encode('Y\t{}; expires={}; path=/; domain={}'.format(y_cookie, y_expiry, domain)))
			list_reply_kvs.add(b'59', arbitrary_encode('T\t{}; expires={}; path=/; domain={}'.format(t_cookie, t_expiry, domain)))
		
		list_reply_kvs.add(b'59', b'C\tmg=1')
		list_reply_kvs.add(b'3', arbitrary_encode(user.username))
		list_reply_kvs.add(b'90', b'1')
		list_reply_kvs.add(b'100', b'0')
		list_reply_kvs.add(b'101', b'')
		list_reply_kvs.add(b'102', b'')
		list_reply_kvs.add(b'93', b'86400')
		
		self.send_reply(YMSGService.List, YMSGStatus.Available, self.sess_id, list_reply_kvs)
		
		if on_login:
			me_status_update(bs, YMSGStatus.Available)
		
		if not after_login:
			self.send_reply(YMSGService.LogOn, YMSGStatus.Available, self.sess_id, self._gen_multi_user_status_dict(user))
	
	def _gen_multi_user_status_dict(self, user: User) -> MultiDict[bytes, bytes]:
		detail = user.detail
		assert detail is not None
		
		cs = list(detail.contacts.values())
		cs_fl_online = [c for c in cs if c.lists & Lst.FL and not c.lists & Lst.BL and not c.status.is_offlineish()]
		
		logon_payload = MultiDict([
			(b'0', arbitrary_encode(user.username)),
			(b'1', arbitrary_encode(user.username)),
			(b'8', str(len(cs_fl_online)).encode('utf-8')),
		]) # type: MultiDict[bytes, bytes]
		
		for c in cs_fl_online:
			add_contact_status_to_data(logon_payload, c.status, c.head)
		
		return logon_payload
	
	async def _check_private_chat(self, chat: Chat, other_user: User, bs: BackendSession) -> None:
		two_users = False
		
		while True:
			await asyncio.sleep(0.1)
			
			if 'ymsg_twoway_only' in chat.front_data:
				if len(list(chat.get_roster_single())) == 2:
					two_users = True
				if len(list(chat.get_roster_single())) > 2 or ('ymsg_twoway_only' in chat.front_data and 'ymsg/conf' in chat.ids):
					del chat.front_data['ymsg_twoway_only']
					if 'ymsg/conf' not in chat.ids:
						chat.add_id('ymsg/conf', chat.ids['main'])
					for cs_other in chat.get_roster():
						if cs_other.user in (bs.user,other_user) and cs_other.bs.front_data.get('ymsg'):
							# Make sure any current YMSG users don't have the chat marked as a private chat anymore
							target_user = None
							if cs_other.user is bs.user:
								target_user = other_user
							elif cs_other.user is other_user:
								target_user = bs.user
							if 'ymsg_private_chats' in cs_other.bs.front_data:
								if target_user:
									del cs_other.bs.front_data['ymsg_private_chats'][target_user.uuid]
							bs.front_data['ymsg_chat_sessions'][chat] = cs_other
							if target_user:
								# Private YMSG chat has turned into a multi-user chat; send invite
								cs_other.bs.evt.on_chat_invite(chat, target_user, invite_msg = 'Two-way chat auto-converted to conference.')
					break
				elif len(list(chat.get_roster_single())) == 1 and two_users:
					for cs_other in chat.get_roster():
						if cs_other.user in (bs.user,other_user) and cs_other.bs.front_data.get('ymsg'):
							if cs_other.user is bs.user:
								target_user = other_user
							elif cs_other.user is other_user:
								target_user = bs.user
							if target_user:
								del cs_other.bs.front_data['ymsg_private_chats'][target_user.uuid]
								cs_other.close()
								break
	
	def _get_oims(self, user: User) -> None:
		oims = self.backend.user_service.get_oim_batch(user)
		oim_msg_dict = MultiDict() # type: MultiDict[bytes, bytes]
		
		for oim in oims:
			oim_msg_dict.add(b'31', b'6')
			oim_msg_dict.add(b'32', b'6')
			oim_msg_dict.add(b'4', arbitrary_encode(oim.from_user_id or oim.from_username))
			oim_msg_dict.add(b'5', arbitrary_encode(user.username))
			oim_msg_dict.add(b'14', arbitrary_encode(oim.message))
			oim_msg_dict.add(b'15', str(int(oim.sent.timestamp())).encode('utf-8'))
			oim_msg_dict.add(b'97', b'1' if oim.utf8 else b'0')
			
			self.backend.user_service.delete_oim(user.uuid, oim.uuid)
		
		if len(list(oim_msg_dict.items())) > 0:
			self.send_reply(YMSGService.Message, YMSGStatus.NotInOffice, self.sess_id, oim_msg_dict)
	
	def _verify_challenge_v1(self, yahoo_id: Optional[str], resp_6: Optional[bytes], resp_96: Optional[bytes]) -> bool:
		from hashlib import md5
		
		backend = self.backend
		
		if not yahoo_id:
			return False
		
		if not resp_6:
			return False
		
		if not resp_96:
			return False
		
		chal = self.challenge
		if chal is None:
			return False
		
		uuid = backend.util_get_uuid_from_username(yahoo_id)
		if uuid is None:
			return False
		
		# Retrieve Yahoo64-encoded MD5 hash of the user's password from the database
		# NOTE: The MD5 hash of the password is unsalted.
		pass_md5 = Y64.Y64Encode(self.backend.user_service.yahoo_get_md5_password(uuid) or b'')
		# Retrieve MD5-crypt(3)'d hash of the user's password from the database
		pass_md5crypt = Y64.Y64Encode(md5(self.backend.user_service.yahoo_get_md5crypt_password(uuid) or b'').digest())
		
		seed_val = (chal[15] % 8) % 5
		
		if seed_val == 0:
			checksum = bytes([chal[chal[7] % 16]])
			hash_p = checksum + pass_md5 + arbitrary_encode(yahoo_id) + chal
			hash_c = checksum + pass_md5crypt + arbitrary_encode(yahoo_id) + chal
		elif seed_val == 1:
			checksum = bytes([chal[chal[9] % 16]])
			hash_p = checksum + arbitrary_encode(yahoo_id) + chal + pass_md5
			hash_c = checksum + arbitrary_encode(yahoo_id) + chal + pass_md5crypt
		elif seed_val == 2:
			checksum = bytes([chal[chal[15] % 16]])
			hash_p = checksum + chal + pass_md5 + arbitrary_encode(yahoo_id)
			hash_c = checksum + chal + pass_md5crypt + arbitrary_encode(yahoo_id)
		elif seed_val == 3:
			checksum = bytes([chal[chal[1] % 16]])
			hash_p = checksum + arbitrary_encode(yahoo_id) + pass_md5 + chal
			hash_c = checksum + arbitrary_encode(yahoo_id) + pass_md5crypt + chal
		elif seed_val == 4:
			checksum = bytes([chal[chal[3] % 16]])
			hash_p = checksum + pass_md5 + chal + arbitrary_encode(yahoo_id)
			hash_c = checksum + pass_md5crypt + chal + arbitrary_encode(yahoo_id)
		
		resp_6_server = Y64.Y64Encode(md5(hash_p).digest())
		resp_96_server = Y64.Y64Encode(md5(hash_c).digest())
		
		return resp_6 == resp_6_server and resp_96 == resp_96_server
	
	def _refresh_cookies(self) -> Tuple[str, str, str, str]:
		# Creates the cookies if they don't exist
		
		assert self.t_cookie_token is not None
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		auth_service = self.backend.auth_service
		
		y_cookie = Y_COOKIE_TEMPLATE.format(encodedname = _encode_yahoo_id(user.username))
		t_cookie = T_COOKIE_TEMPLATE.format(token = self.t_cookie_token)
		
		try:
			_, y_expiry = auth_service.create_token('ymsg/cookie', user.username, token = y_cookie, lifetime = 86400)
			_, t_expiry = auth_service.create_token('ymsg/cookie', self.bs, token = t_cookie, lifetime = 86400)
		except:
			pass
		
		return (y_cookie, t_cookie, _format_cookie_expiry(datetime.datetime.utcfromtimestamp(y_expiry)), _format_cookie_expiry(datetime.datetime.utcfromtimestamp(t_expiry)))

Y_COOKIE_TEMPLATE = 'v=1&n=&l={encodedname}&p=&r=&lg=&intl=&np='
T_COOKIE_TEMPLATE = 'z={token}&a=&sk={token}&ks={token}&kt=&ku=&d={token}'

YAHOO_HELPER_MSG = """\
"YahooHelper" was a bot initially developed by Yahoo! to help guide new users using \
Yahoo! Messenger for the first time and introduce them to its features. Escargot has \
no current plans to reimplement this bot."""

def _format_cookie_expiry(expiry: datetime.datetime) -> str:
	return expiry.strftime('%a, %d %b %Y %H:%M:%S GMT')

def _encode_yahoo_id(yahoo_id: str) -> str:
	return ''.join(
		YAHOO_ID_ENCODING.get(c) or c
		for c in yahoo_id
	)

YAHOO_ID_ENCODING = {
	'k': 'a',
	'l': 'b',
	'm': 'c',
	'n': 'd',
	'o': 'e',
	'p': 'f',
	'q': 'g',
	'r': 'h',
	's': 'i',
	't': 'j',
	'u': 'k',
	'v': 'l',
	'w': 'm',
	'x': 'n',
	'y': 'o',
	'z': 'p',
	'0': 'q',
	'1': 'r',
	'2': 's',
	'3': 't',
	'4': 'u',
	'5': 'v',
	'7': 'x',
	'8': 'y',
	'9': 'z',
	'6': 'w',
	'a': '0',
	'b': '1',
	'c': '2',
	'd': '3',
	'e': '4',
	'f': '5',
	'g': '6',
	'h': '7',
	'i': '8',
	'j': '9',
}

def add_contact_status_to_data(
	data: Any, status: UserStatus, contact: User, *,
	old_substatus: Substatus = Substatus.Offline, message: Optional[str] = None,
	exclude_psm: bool = False, sess_id: Optional[int] = None,
) -> None:
	is_offlineish = status.is_offlineish()
	# `static var YMSG_FLD_SESSION_ID = 11;`
	# Yahoo! was weird sometimes :p
	#if user_yahoo_id in PRE_SESSION_ID:
	#	key_11_val = binascii.hexlify(struct.pack('!I', PRE_SESSION_ID[user_yahoo_id])).decode().upper()
	#elif sess_id is not None:
	#	key_11_val = binascii.hexlify(struct.pack('!I', sess_id)).decode().upper()
	#else:
	#	key_11_val = '0'
	
	data.add(b'7', arbitrary_encode(contact.username))
	
	if not message:
		message = status.message
	
	if is_offlineish or not message or exclude_psm:
		data.add(b'10', str(int(YMSGStatus.Available if is_offlineish else YMSGStatus.FromSubstatus(status.substatus))).encode('utf-8'))
		#data.add(b'11', key_11_val.encode('utf-8'))
		data.add(b'11', b'0')
	else:
		data.add(b'10', str(int(YMSGStatus.Custom)).encode('utf-8'))
		#data.add(b'11', key_11_val.encode('utf-8'))
		data.add(b'11', b'0')
		data.add(b'19', arbitrary_encode(message))
		is_away_message = (status.substatus is not Substatus.Online)
		data.add(b'47', str(int(is_away_message)).encode('utf-8'))
	
	data.add(b'17', b'0')
	data.add(b'13', (b'0' if is_offlineish else b'1'))

class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('loop', 'ctrl', 'dialect', 'sess_id', 'bs')
	
	loop: asyncio.AbstractEventLoop
	ctrl: YMSGCtrlPager
	dialect: int
	sess_id: int
	bs: BackendSession
	
	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: YMSGCtrlPager) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.dialect = ctrl.dialect
		self.sess_id = ctrl.sess_id
	
	def on_system_message(self, *args: Any, message: str = '', **kwargs: Any) -> None:
		if args[1] is not None and args[1] > 0:
			msg = """Escargot will be down for maintenance in around {} minute(s). \
Be sure to wrap up any conversations before this time period.""".format(args[1])
		else:
			msg = message
		kvs = MultiDict([
			(b'14', msg.encode('utf-8')),
			(b'15', str(time.time()).encode('utf-8')),
		]) # type: MultiDict[bytes, bytes]
		self.ctrl.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, kvs)
	
	def on_maintenance_boot(self) -> None:
		# No maintenance-specific booting packets known as of now. Use generic booting procedure.
		
		self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
		self.on_close()
	
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if on_contact_add: return
		
		if update_status or update_info_other:
			if not ctc.lists & Lst.FL: return
			
			if ctc.status.is_offlineish() and not old_substatus.is_offlineish():
				service = YMSGService.LogOff
			elif not old_substatus.is_offlineish() and ctc.status.substatus is Substatus.Online and not ctc.status.message:
				service = YMSGService.IsBack
			else:
				service = YMSGService.IsAway
			
			if not (ctc.status.is_offlineish() and old_substatus.is_offlineish()):
				yahoo_data = MultiDict() # type: MultiDict[bytes, bytes]
				if service is not YMSGService.LogOff:
					yahoo_data.add(b'0', arbitrary_encode(user.username))
				
				if old_substatus.is_offlineish() and not ctc.status.is_offlineish():
					add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, exclude_psm = True, sess_id = sess_id)
					self.ctrl.send_reply(YMSGService.LogOn, YMSGStatus.BRB, self.sess_id, yahoo_data)
					
					if ctc.status.message:
						message = ctc.status.message
						
						yahoo_data = MultiDict()
						yahoo_data.add(b'0', arbitrary_encode(user.username))
						add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, message = message, sess_id = sess_id)
						self.ctrl.send_reply(YMSGService.IsAway, YMSGStatus.BRB, self.sess_id, yahoo_data)
				else:
					add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, sess_id = sess_id)
					
					self.ctrl.send_reply(service, YMSGStatus.BRB, self.sess_id, yahoo_data)
	
	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None:
		pass
	
	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.OnVacation, self.sess_id, MultiDict([
			(b'1', arbitrary_encode(user.username)),
			(b'3', arbitrary_encode(contact_id or user_added.username)),
			(b'14', arbitrary_encode(message)),
		]))
	
	def on_oim_sent(self, oim: 'OIM') -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		backend = bs.backend
		
		message_dict = MultiDict([
			(b'5', arbitrary_encode(user.username)),
			(b'4', arbitrary_encode(oim.from_user_id or oim.from_username)),
			(b'14', arbitrary_encode(oim.message or '')),
			(b'63', b';0'),
			(b'64', b'0'),
			(b'97', (b'1' if oim.utf8 else b'0')),
		]) # type: MultiDict[bytes, bytes]
		
		self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_dict)
		
		backend.user_service.delete_oim(user.uuid, oim.uuid)
	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		for y in misc.build_p2p_msg_packet(self.bs, sess_id, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		for y in misc.build_ft_packet(self.bs, sess_id, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		self.ctrl.send_reply(YMSGService.FileTransfer, YMSGStatus.NotAtDesk, self.sess_id, MultiDict([
			(b'1', self.bs.user.username.encode('utf-8')),
			(b'5', arbitrary_encode(recipient)),
			(b'4', self.bs.user.username.encode('utf-8')),
			(b'14', arbitrary_encode(message)),
		]))
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		for y in misc.build_http_ft_packet(self.bs, yahoo_id_sender, url_path, upload_time, message):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def on_groupchat_created(self, groupchat: GroupChat) -> None:
		pass
	
	def on_groupchat_updated(self, groupchat: GroupChat) -> None:
		pass
	
	def on_left_groupchat(self, groupchat: GroupChat) -> None:
		pass
	
	def on_accepted_groupchat_invite(self, groupchat: GroupChat) -> None:
		pass
	
	def on_groupchat_invite_revoked(self, chat_id: str) -> None:
		pass
	
	def on_groupchat_role_updated(self, chat_id: str, role: GroupChatRole) -> None:
		pass
	
	def on_chat_invite(
		self, chat: Chat, inviter: User, *, group_chat: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None:
		bs = self.bs
		assert bs is not None
		
		if group_chat: return
		if chat.front_data.get('ymsg_twoway_only') and len(list(chat.get_roster_single())) < 2:
			# A Yahoo! non-conference chat; auto-accepted invite
			evt = ChatEventHandler(self.loop, self.ctrl, self.bs)
			cs = chat.join('yahoo', self.bs, evt)
			chat.send_participant_joined(cs)
			self.bs.front_data['ymsg_private_chats'][inviter.uuid] = (cs, evt)
			return
		
		# Regular chat
		if 'ymsg/conf' not in chat.ids:
			chat.add_id('ymsg/conf', chat.ids['main'])
		conf_invite_dict = MultiDict([
			(b'1', arbitrary_encode(self.bs.user.username)),
			(b'57', arbitrary_encode(chat.ids['ymsg/conf'])),
			(b'50', arbitrary_encode(inviter_id or inviter.username)),
			(b'58', arbitrary_encode(invite_msg)),
		]) # type: MultiDict[bytes, bytes]
		
		roster = list(chat.get_roster_single())
		for cs in roster:
			if cs.user.uuid == inviter.uuid: continue
			conf_invite_dict.add(b'52', arbitrary_encode(cs.preferred_name or cs.user.username))
			conf_invite_dict.add(b'53', arbitrary_encode(cs.preferred_name or cs.user.username))
		
		conf_invite_dict.add(b'13', arbitrary_encode(chat.front_data.get('ymsg_voice_chat') or '0'))
		
		self.ctrl.send_reply(
			YMSGService.ConfAddInvite if len(roster) > 1 else YMSGService.ConfInvite,
			YMSGStatus.BRB, self.ctrl.sess_id, conf_invite_dict,
		)
	
	def on_declined_chat_invite(self, chat: Chat, group_chat: bool = False) -> None:
		pass
	
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None:
		bs = self.bs
		assert bs is not None
		user_me = bs.user
		detail = user_me.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		ctc = contacts.get(user.uuid)
		if ctc is not None:
			if ctc.lists & Lst.BL: return
			if ctc.pending:
				bs.me_contact_remove(ctc.head.uuid, Lst.PL)
		
		contact_request_data = MultiDict([
			(b'1', arbitrary_encode(user_me.username)),
			(b'3', arbitrary_encode(adder_id or user.username)),
		]) # type: MultiDict[bytes, bytes]
		
		if message is not None:
			contact_request_data.add(b'14', arbitrary_encode(message.text))
			if message.yahoo_utf8 is not None:
				contact_request_data.add(b'97', arbitrary_encode(message.yahoo_utf8))
		
		contact_request_data.add(b'15', arbitrary_encode(str(time.time())))
		
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.NotAtHome, self.sess_id, contact_request_data)
	
	def on_removed_me(self, user: User) -> None:
		pass
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		if option is LoginOption.BootOthers:
			self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.LoginError, self.sess_id, None)
			self.ctrl.close()
	
	def on_close(self) -> None:
		self.ctrl.close()

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('loop', 'ctrl', 'bs', 'cs')
	
	loop: asyncio.AbstractEventLoop
	ctrl: YMSGCtrlPager
	bs: BackendSession
	cs: ChatSession
	
	def __init__(self, loop: asyncio.AbstractEventLoop, ctrl: YMSGCtrlPager, bs: BackendSession) -> None:
		self.loop = loop
		self.ctrl = ctrl
		self.bs = bs
	
	def on_close(self) -> None:
		assert self.bs is not None
		self.bs.front_data['ymsg_chat_sessions'].pop(self.cs.chat, None)
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if self.cs.chat.front_data.get('ymsg_twoway_only') or not first_pop:
			return
		self.ctrl.send_reply(YMSGService.ConfLogon, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			(b'1', arbitrary_encode(user.username)),
			(b'57', arbitrary_encode(cs_other.chat.ids['ymsg/conf'])),
			(b'53', arbitrary_encode(cs_other.preferred_name or cs_other.user.username)),
		]))
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if 'ymsg/conf' not in cs_other.chat.ids:
			# Yahoo only receives this event in "conferences"
			return
		if not last_pop:
			return
		self.ctrl.send_reply(YMSGService.ConfLogoff, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			(b'1', arbitrary_encode(user.username)),
			(b'57', arbitrary_encode(cs_other.chat.ids['ymsg/conf'])),
			(b'56', arbitrary_encode(cs_other.preferred_name or cs_other.user.username)),
		]))
	
	def on_chat_invite_declined(
		self, chat: Chat, invitee: User, *, invitee_id: Optional[str] = None, message: Optional[str] = None, group_chat: bool = False,
	) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if group_chat: return
		self.ctrl.send_reply(YMSGService.ConfDecline, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			(b'1', user.username.encode('utf-8')),
			(b'57', arbitrary_encode(chat.ids['ymsg/conf'])),
			(b'54', arbitrary_encode(invitee_id or invitee.username)),
			(b'14', arbitrary_encode(message or '')),
		]))
	
	def on_chat_updated(self) -> None:
		pass
	
	def on_chat_roster_updated(self) -> None:
		pass
	
	def on_participant_status_updated(self, cs_other: ChatSession, first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		sender = data.sender
		yahoo_data = messagedata_to_ymsg(data)
		
		if data.type in (MessageType.Chat,MessageType.Nudge):
			if self.cs.chat.front_data.get('ymsg_twoway_only'):
				message_to_dict = MultiDict([
					(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
					(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
					(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or '')),
				]) # type: MultiDict[bytes, bytes]
				
				if yahoo_data.get(b'63') is not None:
					message_to_dict.add(b'63', yahoo_data.get(b'63') or b'')
				
				if yahoo_data.get(b'64') is not None:
					message_to_dict.add(b'64', yahoo_data.get(b'64') or b'')
				
				if yahoo_data.get(b'97') is not None:
					message_to_dict.add(b'97', yahoo_data.get(b'97') or b'')
				
				self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_to_dict)
			else:
				if data.type is not MessageType.Nudge:
					conf_message_dict = MultiDict([
						(b'1', arbitrary_encode(user.username)),
						(b'57', arbitrary_encode(self.cs.chat.ids['ymsg/conf'])),
						(b'3', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
						(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or '')),
					])
					
					if yahoo_data.get(b'97') is not None:
						conf_message_dict.add(b'97', yahoo_data.get(b'97') or b'')
					
					self.ctrl.send_reply(YMSGService.ConfMsg, YMSGStatus.BRB, self.ctrl.sess_id, conf_message_dict)
		elif data.type in (MessageType.Typing,MessageType.TypingDone) and self.cs.chat.front_data.get('ymsg_twoway_only'):
			self.ctrl.send_reply(YMSGService.Notify, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
				(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
				(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
				(b'49', b'TYPING'),
				(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or ' ')),
				(b'13', yahoo_data.get(b'13') or (b'0' if data.type is MessageType.TypingDone else b'1'))
			]))
		elif data.type is MessageType.Webcam:
			kvs = MultiDict([
				(b'5', yahoo_data.get(b'5') or arbitrary_encode(user.username)),
				(b'4', yahoo_data.get(b'1') or arbitrary_encode(sender.username)),
				(b'49', b'WEBCAMINVITE'),
				(b'14', yahoo_data.get(b'14') or arbitrary_encode(data.text or ' ')),
			]) # type: MultiDict[bytes, bytes]
			self.ctrl.send_reply(YMSGService.Notify, YMSGStatus.BRB, self.ctrl.sess_id, kvs)
	
	def _send_when_user_joins(self, user_uuid: str, data: MessageData) -> None:
		# Send to everyone currently in chat
		self.cs.send_message_to_everyone(data)
		
		if self._user_in_chat(user_uuid):
			return
		
		# If `user_uuid` hasn't joined yet, send it later
		self.loop.create_task(self._send_delayed(user_uuid, data))
	
	async def _send_delayed(self, user_uuid: str, data: MessageData) -> None:
		delay = 0.1
		for _ in range(3):
			await asyncio.sleep(delay)
			delay *= 3
			if self._user_in_chat(user_uuid):
				self.cs.send_message_to_user(user_uuid, data)
				return
	
	def _user_in_chat(self, user_uuid: str) -> bool:
		for cs_other in self.cs.chat.get_roster():
			if cs_other.user.uuid == user_uuid:
				return True
		return False

def messagedata_from_ymsg(
	sender: User, data: MultiDict[bytes, bytes], *, notify_type: Optional[bytes] = None, typing_flag: Optional[str] = None,
) -> MessageData:
	text = arbitrary_decode(data.get(b'14') or b'')
	
	if notify_type is None:
		if text == '<ding>':
			type = MessageType.Nudge
			text = ''
		else:
			type = MessageType.Chat
	elif notify_type == b'TYPING':
		if typing_flag == '0':
			type = MessageType.TypingDone
		else:
			type = MessageType.Typing
	elif notify_type == b'WEBCAMINVITE':
		type = MessageType.Webcam
	else:
		# TODO: other `notify_type`s
		raise Exception("Unknown notify_type", notify_type)
	
	message = MessageData(sender = sender, type = type, text = text)
	message.front_cache['ymsg'] = data
	return message

def messagedata_to_ymsg(data: MessageData) -> MultiDict[bytes, bytes]:
	if 'ymsg' not in data.front_cache:
		data.front_cache['ymsg'] = MultiDict([
			(b'14', (b'<ding>' if data.type is MessageType.Nudge else arbitrary_encode(data.text or ''))),
			(b'63', b';0'),
			(b'64', b'0'),
			(b'97', b'1'),
		])
	return data.front_cache['ymsg']

def me_status_update(bs: BackendSession, status_new: YMSGStatus, *, message: str = '', is_away_message: bool = False) -> None:
	bs.front_data['ymsg_status'] = status_new
	if status_new is YMSGStatus.Custom:
		substatus = (Substatus.Busy if is_away_message else Substatus.Online)
	else:
		substatus = YMSGStatus.ToSubstatus(status_new)
	bs.me_update({
		'message': message,
		'substatus': substatus,
		'notify_status': True,
		'notify_info': (True if message else False),
	})

def generate_challenge_v1() -> bytes:
	from uuid import uuid4
	
	# Yahoo64-encode the raw 16 bytes of a UUID
	return Y64.Y64Encode(uuid4().bytes)
