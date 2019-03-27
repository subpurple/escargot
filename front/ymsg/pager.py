from typing import Optional, Dict, Any, List, Iterable, Set, Tuple
import secrets
import datetime
import asyncio
import time
import binascii
import struct

import settings
from util.misc import Logger, gen_uuid, MultiDict, arbitrary_decode, arbitrary_encode

from core import event, error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import Substatus, Lst, User, Contact, Group, TextWithData, MessageData, MessageType, UserStatus, LoginOption
from core.client import Client
from core.user import UserService
from core.auth import AuthService

from .ymsg_ctrl import YMSGCtrlBase
from .misc import YMSGService, YMSGStatus, yahoo_id_to_uuid, is_blocking
from . import misc, Y64

# "Pre" because it's needed before BackendSession is created.
PRE_SESSION_ID: Dict[str, int] = {}

class YMSGCtrlPager(YMSGCtrlBase):
	__slots__ = ('backend', 'dialect', 'yahoo_id', 'sess_id', 'challenge', 't_cookie_token', 'bs', 'chat_sessions', 'client')
	
	backend: Backend
	dialect: int
	yahoo_id: Optional[str]
	sess_id: int
	challenge: Optional[bytes]
	t_cookie_token: Optional[str]
	bs: Optional[BackendSession]
	chat_sessions: Dict[Chat, ChatSession]
	client: Client
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.yahoo_id = None
		self.sess_id = 0
		self.challenge = None
		self.t_cookie_token = None
		self.bs = None
		self.chat_sessions = {}
		self.client = Client('yahoo', '?', via)
	
	def _on_close(self, remove_sess_id: bool = True) -> None:
		if self.bs:
			self.bs.close(sess_id = PRE_SESSION_ID.get(self.yahoo_id or ''))
		
		if self.yahoo_id and remove_sess_id:
			PRE_SESSION_ID.pop(self.yahoo_id, None)
	
	# State = Auth
	
	def _y_004c(self, *args: Any) -> None:
		# SERVICE_HANDSHAKE (0x4c); acknowledgement of the server
		
		self.client = Client('yahoo', 'YMSG' + str(args[0]), self.client.via)
		self.dialect = int(args[0])
		self.send_reply(YMSGService.Handshake, YMSGStatus.BRB, 0, None)
	
	def _y_0057(self, *args: Any) -> None:
		# SERVICE_AUTH (0x57); send a challenge string for the client to craft two response strings with
		backend = self.backend
		
		arg1 = args[4].get('1')
		assert isinstance(arg1, bytes)
		self.yahoo_id = arbitrary_decode(arg1)
		
		uuid = yahoo_id_to_uuid(backend, self.yahoo_id)
		if uuid is None or backend.user_service.is_user_relay(uuid):
			self.yahoo_id = None
			kvs = MultiDict([
				('66', str(int(YMSGStatus.NotAtHome)).encode('utf-8'))
			]) # type: MultiDict[str, bytes]
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, 0, kvs)
			return
		
		if self.yahoo_id in PRE_SESSION_ID:
			self.close(remove_sess_id = False)
			return
		self.sess_id = secrets.randbelow(4294967294) + 1
		PRE_SESSION_ID[self.yahoo_id] = self.sess_id
		
		auth_dict = MultiDict([
			('1', self.yahoo_id.encode('utf-8')),
		]) # type: MultiDict[str, bytes]
		
		if 9 <= self.dialect <= 10:
			self.challenge = generate_challenge_v1()
			auth_dict.add('94', self.challenge)
		elif self.dialect <= 11:
			# Implement V2 challenge string generation later
			auth_dict.add('94', '')
			auth_dict.add('13', b'1')
		
		self.send_reply(YMSGService.Auth, YMSGStatus.BRB, self.sess_id, auth_dict)
	
	def _y_0054(self, *args: Any) -> None:
		# SERVICE_AUTHRESP (0x54); verify response strings for successful authentication
		
		y = None
		t = None
		
		status = args[2]
		if status is YMSGStatus.WebLogin:
			status = YMSGStatus.Available
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		resp_6 = args[4].get('6')
		resp_96 = args[4].get('96')
		
		version = args[4].get('135')
		if version is not None:
			version = arbitrary_decode(version)
		self.client = Client('yahoo', version, self.client.via)
		
		# TODO: Dialect 11 not supported yet?
		assert 9 <= self.dialect <= 10
		
		assert self.challenge is not None
		is_resp_correct = self._verify_challenge_v1(yahoo_id, resp_6, resp_96)
		if is_resp_correct:
			uuid = yahoo_id_to_uuid(self.backend, yahoo_id)
			if uuid is None:
				is_resp_correct = False
			else:
				self.yahoo_id = yahoo_id
				# NOTE: Yahoo! Messenger *can* specify the `Y` and `T` cookies in this packet after multiple logins as long as it isn't
				# terminated. Verify and store cookies if needed.
				
				if '59' in args[4]:
					tpl = args[4].getall('59')
					if len(tpl) != 2:
						self.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
					y, t = tpl
				bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), option = LoginOption.BootOthers)
				if bs is None:
					is_resp_correct = False
				else:
					self.bs = bs
					self._util_authresp_final(status, cached_y = y, cached_t = t)
		
		if not is_resp_correct:
			self.yahoo_id = None
			kvs = MultiDict([
				('66', str(int(YMSGStatus.Bad)).encode('utf-8'))
			]) # type: MultiDict[str, bytes]
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, self.sess_id, kvs)
	
	def _util_authresp_final(self, status: YMSGStatus, *, cached_y: Optional[str] = None, cached_t: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		assert self.yahoo_id is not None
		
		self.t_cookie_token = (cached_t[4:24] if cached_y and cached_t else AuthService.GenTokenStr())
		
		me_status_update(bs, status, send_notif_to_self = False)
		
		bs.front_data['ymsg'] = True
		bs.front_data['ymsg_private_chats'] = {}
		
		self._get_oims(user)
		
		self._update_buddy_list(cached_y = cached_y, cached_t = cached_t, after_login = True)
		
		if self.dialect >= 10:
			kvs = MultiDict([
				('143', b'60'),
				('144', b'13')
			]) # type: MultiDict[str, bytes]
			self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, kvs)
		
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
		
		new_status = YMSGStatus(int(args[4].get('10')))
		message = arbitrary_decode(args[4].get('19') or b'')
		is_away_message = (args[4].get('47') == b'1')
		me_status_update(bs, new_status, message = message, is_away_message = is_away_message)
	
	def _y_0012(self, *args: Any) -> None:
		# SERVICE_PINGCONFIGURATION (0x12); set the "ticks" and "tocks" of a ping sent
		
		kvs = MultiDict([
			('143', b'60'),
			('144', b'13')
		]) # type: MultiDict[str, bytes]
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
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		contact_yahoo_id = args[4].get('7')
		if contact_yahoo_id is not None:
			contact_yahoo_id = arbitrary_decode(contact_yahoo_id)
		message = args[4].get('14')
		if message is not None:
			message = arbitrary_decode(message)
		buddy_group = args[4].get('65')
		if buddy_group is not None:
			buddy_group = arbitrary_decode(buddy_group)
		utf8 = args[4].get('97')
		if utf8 is not None:
			utf8 = arbitrary_decode(utf8)
		
		group = None
		action_group_refresh = False
		
		add_request_response = MultiDict([
			('1', arbitrary_encode(yahoo_id or '')),
			('7', arbitrary_encode(contact_yahoo_id or '')),
			('65', arbitrary_encode(buddy_group or ''))
		])
		
		# Yahoo! Messenger has a function that lets you add people by email address (a.k.a. stripping the "@domain.tld" part of the address and
		# filling that out in the "Yahoo! ID" section of the contact add dialog). Treat as is.
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id)
		if contact_uuid is None:
			add_request_response.add('66', b'3')
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		cs = list(contacts.values())
		
		contact = contacts.get(contact_uuid)
		if contact is not None and contact.lists & Lst.FL:
			if contact._groups:
				for group_other in contact._groups.copy():
					if detail._groups_by_id[group_other.id].name == buddy_group:
						add_request_response.add('66', b'2')
						self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
						return
			else:
				if buddy_group == '(No Group)':
					add_request_response.add('66', b'2')
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
		
		if not contact or (not contact.lists & Lst.FL and not contact.lists & Lst.BL):
			if not ctc_head.status.is_offlineish():
				contact_struct = MultiDict([
					('0', (self.yahoo_id or '').encode('utf-8')),
				]) # type: Optional[MultiDict[str, bytes]]
				add_contact_status_to_data(contact_struct, ctc_head.status, ctc_head)
			else:
				contact_struct = None
			
			self.send_reply(YMSGService.ContactNew, YMSGStatus.BRB, self.sess_id, contact_struct)
			
			contact = bs.me_contact_add(ctc_head.uuid, Lst.FL, message = (TextWithData(message, utf8) if message is not None else None), adder_id = yahoo_id, needs_notify = True)[0]
			bs.me_contact_add(contact.head.uuid, Lst.AL)
		add_request_response.add('66', b'0')
		self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
		try:
			# TODO: Moving/copying contacts to groups
			if len(contact._groups) >= 1 or (contact._groups and buddy_group == '(No Group)'): action_group_refresh = True
			if buddy_group == '(No Group)':
				for group_other in contact._groups.copy():
					group_full = False
					bs.me_group_contact_remove(group_other.id, contact.head.uuid)
					for ctc_other in detail.contacts.values():
						if ctc_other is contact: continue
						for group_ctc in ctc_other._groups.copy():
							if group_ctc.id is group_other.id:
								group_full = True
								break
						if group_full:
							break
			if group is not None:
				bs.me_group_contact_add(group.id, contact.head.uuid)
			
			if action_group_refresh: self._update_buddy_list()
		except error.ContactAlreadyOnList:
			# Ignore, because this condition was checked earlier, so the only way this
			# can happen is if the the contact list gets in an inconsistent state.
			# (I.e. contact is not on FL, but still part of groups.)
			pass
	
	def _y_0086(self, *args: Any) -> None:
		# SERVICE_CONTACTDENY (0x86); deny a contact request
		
		adder_to_deny = args[4].get('7')
		if adder_to_deny is not None:
			adder_to_deny = arbitrary_decode(adder_to_deny)
		deny_message = args[4].get('14')
		if deny_message is not None:
			deny_message = arbitrary_decode(deny_message)
		
		adder_uuid = yahoo_id_to_uuid(self.backend, adder_to_deny)
		assert adder_uuid is not None
		bs = self.bs
		assert bs is not None
		bs.me_contact_deny(adder_uuid, deny_message)
	
	def _y_0089(self, *args: Any) -> None:
		# SERVICE_GROUPRENAME (0x89); rename a contact group
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		group_name = args[4].get('65')
		if group_name is not None:
			group_name = arbitrary_decode(group_name)
		new_group_name = args[4].get('67')
		if new_group_name is not None:
			new_group_name = arbitrary_decode(new_group_name)
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
				('1', arbitrary_encode(yahoo_id or '')),
				('66', b'0'),
				('67', arbitrary_encode(new_group_name or '')),
				('65', arbitrary_encode(group_name or '')),
			]) # type: MultiDict[str, bytes]
			
			self.send_reply(YMSGService.GroupRename, YMSGStatus.BRB, self.sess_id, group_rename_response)
		
		self._update_buddy_list()
	
	def _y_0084(self, *args: Any) -> None:
		# SERVICE_FRIENDREMOVE (0x84); remove a buddy from your list
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		contact_id = args[4].get('7')
		if contact_id is not None:
			contact_id = arbitrary_decode(contact_id)
		buddy_group = args[4].get('65')
		if buddy_group is not None:
			buddy_group = arbitrary_decode(buddy_group)
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		group = None
		
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_id)
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
			('1', arbitrary_encode(yahoo_id or '')),
			('66', b'0'),
			('7', arbitrary_encode(contact_id or '')),
			('65', arbitrary_encode(buddy_group or '')),
		]) # type: MultiDict[str, bytes]
		
		self.send_reply(YMSGService.FriendRemove, YMSGStatus.BRB, self.sess_id, remove_buddy_response)
		
		self._update_buddy_list()
	
	def _y_0085(self, *args: Any) -> None:
		# SERVICE_IGNORE (0x85); add/remove someone from your ignore list
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		ignored_yahoo_id = args[4].get('7')
		if ignored_yahoo_id is not None:
			ignored_yahoo_id = arbitrary_decode(ignored_yahoo_id)
		ignore_mode = args[4].get('13')
		if ignore_mode is not None:
			ignore_mode = arbitrary_decode(ignore_mode)
		
		ignore_reply_response = MultiDict([
			('0', arbitrary_encode(yahoo_id)),
			('7', arbitrary_encode(ignored_yahoo_id)),
			('13', arbitrary_encode(ignore_mode))
		])
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		contacts = detail.contacts
		
		ignored_uuid = yahoo_id_to_uuid(self.backend, ignored_yahoo_id)
		if ignored_uuid is None:
			ignore_reply_response.add('66', b'3')
			self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
			return
		
		if int(ignore_mode) == 1:
			contact = contacts.get(ignored_uuid)
			if contact is not None:
				if contact.lists & Lst.BL:
					ignore_reply_response.add('66', b'2')
					self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
					return
			
			bs.me_contact_add(ignored_uuid, Lst.BL, name = ignored_yahoo_id)
		elif int(ignore_mode) == 2:
			bs.me_contact_remove(ignored_uuid, Lst.BL)
		else:
			return
		
		self.send_reply(YMSGService.AddIgnore, YMSGStatus.BRB, self.sess_id, None)
		ignore_reply_response.add('66', b'0')
		self._update_buddy_list()
		self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
	
	def _y_000a(self, *args: Any) -> None:
		# SERVICE_USERSTAT (0x0a); synchronize logged on user's status
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		self.send_reply(YMSGService.UserStat, bs.front_data.get('ymsg_status') or YMSGStatus.FromSubstatus(user.status.substatus), self.sess_id, None)
		self._update_buddy_list()
	
	def _y_0055(self, *args: Any) -> None:
		# SERVICE_LIST (0x55); send a user's buddy list
		
		self._update_buddy_list()
	
	def _y_008a(self, *args: Any) -> None:
		# SERVICE_PING (0x8a); send a response ping after the client pings
		assert self.yahoo_id is not None
		self.send_reply(YMSGService.Ping, YMSGStatus.Available, self.sess_id, MultiDict([
			('1', self.yahoo_id.encode('utf-8')),
		]))
	
	def _y_0008(self, *args: Any) -> None:
		# SERVICE_IDDEACTIVATE (0x08); deactivate an alias
		
		return
	
	def _y_0007(self, *args: Any) -> None:
		# SERVICE_IDACTIVATE (0x07); activate an alias
		
		return
	
	def _y_004f(self, *args: Any) -> None:
		# SERVICE_PEERTOPEER (0x4f); see if P2P messaging is possible
		
		#yid = args[4].get('1')
		#yid_from = args[4].get('4')
		#
		#p2p_to_id = args[4].get('5')
		#contact_uuid = yahoo_id_to_uuid(self.backend, p2p_to_id)
		#if contact_uuid is None:
		#	return
		#
		#bs = (self.bs if yid not in self.activated_alias_bses else self.activated_alias_bses[yid])
		#assert bs is not None
		#
		#for bs_other in bs.backend._sc.iter_sessions():
		#	if bs_other.user.uuid == contact_uuid:
		#		bs_other.evt.ymsg_on_p2p_msg_request(args[4])
		
		return
	
	def _y_004b(self, *args: Any) -> None:
		# SERVICE_NOTIFY (0x4b); notify a contact of an action (typing, games, etc.)
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		notify_type = yahoo_data.get('49') # typing, games, etc.
		typing_flag = yahoo_data.get('13')
		if typing_flag is not None:
			typing_flag = arbitrary_decode(typing_flag)
		contact_yahoo_id = yahoo_data.get('5')
		if contact_yahoo_id is not None:
			contact_yahoo_id = arbitrary_decode(contact_yahoo_id)
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id)
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
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		contact_yahoo_id = args[4].get('5')
		if contact_yahoo_id is not None:
			contact_yahoo_id = arbitrary_decode(contact_yahoo_id)
		
		self._message_common(args[4], contact_yahoo_id)
	
	def _y_0017(self, *args: Any) -> None:
		# SERVICE_MASSMESSAGE (0x17); send a message to multiple users
		yahoo_id = args[4].get('1')
		
		contact_yahoo_ids = args[4].getall('5')
		for i, contact_yahoo_id in enumerate(contact_yahoo_ids):
			contact_yahoo_ids[i] = arbitrary_decode(contact_yahoo_id)
		if contact_yahoo_ids:
			for contact_yahoo_id in contact_yahoo_ids:
				self._message_common(args[4], contact_yahoo_id)
	
	def _y_0050(self, *args: Any) -> None:
		# SERVICE_VIDEOCHAT (0x50); create a webcam token for authentication
		#bs = self.bs
		#assert bs is not None
		#
		#if not args[4].get('1'): return
		#
		#webcam_token = self.backend.auth_service.create_token('ymsg/webcam', args[4].get('1'), lifetime = 86400)
		#
		#self.send_reply(YMSGService.VideoChat, YMSGStatus.BRB, self.sess_id, MultiDict([
		#	('1', args[4].get('1')),
		#	('5', args[4].get('1')),
		#	('61', webcam_token),
		#]))
		
		return
	
	def _y_004d(self, *args: Any) -> None:
		# SERVICE_P2PFILEXFER (0x4d); initiate P2P file transfer. Due to this service being present in 3rd-party libraries; we can implement it here
		
		yahoo_data = args[4]
		
		bs = self.bs
		assert bs is not None
		
		contact_id = yahoo_data.get('5')
		if contact_id is not None:
			contact_id = arbitrary_decode(contact_id)
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_id)
		if contact_uuid is None:
			return
		
		for bs_other in bs.backend._sc.iter_sessions():
			if bs_other.user.uuid == contact_uuid:
				bs_other.evt.ymsg_on_xfer_init(yahoo_data)
	
	def _y_0018(self, *args: Any) -> None:
		# SERVICE_CONFINVITE (0x18); send a conference invite to one or more people
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		conf_roster = yahoo_data.getall('52', None)
		if conf_roster is None:
			return
		# Comma-separated yahoo ids
		conf_roster_2 = yahoo_data.get('51')
		if conf_roster_2:
			conf_roster.extend(conf_roster_2.split(','))
		conf_id = yahoo_data.get('57')
		invite_msg = yahoo_data.get('58')
		voice_chat = yahoo_data.get('13')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id, create = True)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_roster:
			conf_user_uuid = yahoo_id_to_uuid(self.backend, conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_001c(self, *args: Any) -> None:
		# SERVICE_CONFADDINVITE (0x1c); send a conference invite to an existing conference to one or more people
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		conf_new_roster_str = yahoo_data.get('51')
		if conf_new_roster_str is None:
			return
		conf_new_roster = arbitrary_decode(conf_new_roster_str).split(',')
		conf_roster = yahoo_data.getall('52', None)
		if conf_roster is None:
			conf_roster = yahoo_data.getall('53', None)
			if conf_roster is None:
				conf_roster = []
		for i, conf_member in enumerate(conf_roster):
			conf_roster[i] = arbitrary_decode(conf_member)
		conf_id = yahoo_data.get('57')
		if conf_id is None:
			return
		conf_id = arbitrary_decode(conf_id)
		invite_msg = yahoo_data.get('58')
		if invite_msg is not None:
			invite_msg = arbitrary_decode(invite_msg)
		voice_chat = yahoo_data.get('13')
		if voice_chat is not None:
			voice_chat = arbitrary_decode(voice_chat)
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_new_roster:
			conf_user_uuid = yahoo_id_to_uuid(self.backend, conf_user_yahoo_id)
			if conf_user_uuid is None: continue
			conf_user = self.backend._load_user_record(conf_user_uuid)
			if conf_user is None: continue
			cs.invite(conf_user, invite_msg = invite_msg)
	
	def _y_0019(self, *args: Any) -> None:
		# SERVICE_CONFLOGON (0x19); request for me to join a conference
		
		#inviter_ids = args[4].getall('3', None)
		#if inviter_ids is None:
		#	return
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		conf_id = args[4].get('57')
		if conf_id is None:
			return
		conf_id = arbitrary_decode(conf_id)
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
	
	def _y_001a(self, *args: Any) -> None:
		# SERVICE_CONFDECLINE (0x1a); decline a request to join a conference
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		
		bs = self.bs
		assert bs is not None
		
		inviter_ids = args[4].getall('3', None)
		if inviter_ids is None:
			return
		for i, inviter_id in enumerate(inviter_ids):
			inviter_ids[i] = arbitrary_decode(inviter_id)
		conf_id = args[4].get('57')
		if conf_id is not None:
			conf_id = arbitrary_decode(conf_id)
		deny_msg = args[4].get('14')
		if deny_msg is not None:
			deny_msg = arbitrary_decode(deny_msg)
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		
		for cs in chat.get_roster():
			if misc.yahoo_id(cs.user.email) not in inviter_ids:
				continue
			cs.evt.on_invite_declined(bs.user, invited_id = yahoo_id, message = deny_msg)
	
	def _y_001d(self, *args: Any) -> None:
		# SERVICE_CONFMSG (0x1d); send a message in a conference
		
		#conf_user_ids = args[4].getall('53', None)
		#if conf_user_ids is None:
		#	return
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		conf_id = yahoo_data.get('57')
		if conf_id is not None:
			conf_id = arbitrary_decode(conf_id)
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		cs.preferred_name = yahoo_id
		cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data))
	
	def _y_001b(self, *args: Any) -> None:
		# SERVICE_CONFLOGOFF (0x1b); leave a conference
		
		#conf_roster = args[4].getall('3', None)
		#if conf_roster is None:
		#	return
		
		yahoo_id = args[4].get('1')
		if yahoo_id is not None:
			yahoo_id = arbitrary_decode(yahoo_id)
		conf_id = args[4].get('57')
		if conf_id is not None:
			conf_id = arbitrary_decode(conf_id)
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		cs = self._get_chat_session(yahoo_id, chat)
		if cs is not None:
			cs.close(keep_future = True)
	
	# Other functions
	
	def _message_common(self, yahoo_data: Dict[str, bytes], contact_yahoo_id: Optional[str]) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		assert self.yahoo_id is not None
		if contact_yahoo_id == 'YahooHelper':
			yhlper_msg_dict = MultiDict([
				('5', yahoo_data.get('1') or b''),
				('4', b'YahooHelper'),
				('14', YAHOO_HELPER_MSG.encode('utf-8')),
			]) # type: MultiDict[str, bytes]
			
			if yahoo_data.get('63') is not None:
				yhlper_msg_dict.add('63', yahoo_data.get('63'))
			
			if yahoo_data.get('64') is not None:
				yhlper_msg_dict.add('64', yahoo_data.get('64'))
			
			yhlper_msg_dict.add('97', b'1')
			
			self.send_reply(YMSGService.Message, YMSGStatus.BRB, self.sess_id, yhlper_msg_dict)
			return
		
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id or '')
		if contact_uuid is None:
			return
		
		try:
			cs, evt = self._get_private_chat_with(contact_uuid)
			if None not in (cs, evt):
				evt._send_when_user_joins(contact_uuid, messagedata_from_ymsg(cs.user, yahoo_data))
		except error.ContactNotOnline as ex:
			# Will probably never get to this stage due to the server-side quirks of the contact blocking scheme (which can make us
			# think that someone who is offline might not be blocking us, even though when they actually are, their `UserDetail` isn't
			# available to confirm), but we can make arrangements...
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
			md = messagedata_from_ymsg(contact_user, yahoo_data)
			if md.type is MessageType.Chat:
				(ip, _) = self.peername
				from_user_id = None
				
				key1_val = md.front_cache['ymsg'].get('1')
				if key1_val is not None:
					from_user_id = arbitrary_decode(key1_val)
				
				self.backend.user_service.save_oim(
					gen_uuid().upper(), contact_uuid, user.email, self.yahoo_id, ip, md.text or '', False if md.front_cache['ymsg'].get('97') is b'0' else True,
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
		# TODO: Users who appear offline (regardless of blocking you or not) can have a `UserDetail`, but when they're actually offline they don't,
		# as if they were an unblocked contact who was offline. Due to this quirk, it's hard to tell if they blocked you for the purpose of
		# determining if they can be sent OIMs. Find a better scheme for detecting this, as with this implementation it'd be impossible to
		# send OIMs to anyone (people in Invisible mode are supposed to receive IMs as normal).
		other_user_ctc = detail.contacts.get(other_user.uuid)
		if other_user_ctc is not None and other_user_ctc.lists & Lst.BL:
			raise error.ContactNotOnList()
		if other_user_uuid not in bs.front_data['ymsg_private_chats'] and other_user.status.substatus is not Substatus.Offline:
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
		elif other_user.status.substatus is Substatus.Offline:
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
		
		cs = self.chat_sessions.get(chat)
		if cs is None and create:
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt, preferred_name = yahoo_id)
			self.chat_sessions[chat] = cs
			chat.send_participant_joined(cs)
		return cs
	
	def _update_buddy_list(self, cached_y: Optional[str] = None, cached_t: Optional[str] = None, after_login: bool = False) -> None:
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
						contact_list.append(misc.yahoo_id(c.head.email))
			if contact_list:
				contact_group_list.append(grp.name + ':' + ','.join(contact_list) + '\n')
		# Handle contacts that aren't part of any groups
		contact_list = [misc.yahoo_id(c.head.email) for c in cs_fl if not c._groups]
		if contact_list:
			contact_group_list.append('(No Group):' + ','.join(contact_list) + '\n')
		
		ignore_list = [misc.yahoo_id(c.head.email) for c in cs if c.lists & Lst.BL]
		
		list_reply_kvs = MultiDict([
			('87', ''.join(contact_group_list).encode('utf-8')),
			('88', ','.join(ignore_list).encode('utf-8')),
			('89', (self.yahoo_id or '').encode('utf-8')),
		]) # type: MultiDict[str, bytes]
		
		if cached_y is not None and cached_t is not None and backend.auth_service.get_token('ymsg/cookie', cached_y) and backend.auth_service.get_token('ymsg/cookie', cached_t):
			list_reply_kvs.add('59', cached_y.encode('utf-8'))
			list_reply_kvs.add('59', cached_t.encode('utf-8'))
		else:
			(y_cookie, t_cookie, cookie_expiry) = self._refresh_cookies()
			list_reply_kvs.add('59', 'Y\t{}; expires={}; path=/; domain={}'.format(y_cookie, cookie_expiry, ('yahooloopback.log1p.xyz' if settings.DEBUG else settings.TARGET_HOST)).encode('utf-8'))
			list_reply_kvs.add('59', 'T\t{}; expires={}; path=/; domain={}'.format(t_cookie, cookie_expiry, ('yahooloopback.log1p.xyz' if settings.DEBUG else settings.TARGET_HOST)).encode('utf-8'))
		
		list_reply_kvs.add('59', b'C\tmg=1')
		list_reply_kvs.add('3', (self.yahoo_id or '').encode('utf-8'))
		list_reply_kvs.add('90', b'1')
		list_reply_kvs.add('100', b'0')
		list_reply_kvs.add('101', b'')
		list_reply_kvs.add('102', b'')
		list_reply_kvs.add('93', b'86400')
		
		self.send_reply(YMSGService.List, YMSGStatus.Available, self.sess_id, list_reply_kvs)
		
		logon_payload = MultiDict([
			('0', (self.yahoo_id or '').encode('utf-8')),
			('1', (self.yahoo_id or '').encode('utf-8')),
			('8', str(len(cs_fl)).encode('utf-8')),
		]) # type: MultiDict[str, bytes]
		
		for c in cs_fl:
			add_contact_status_to_data(logon_payload, c.status, c.head)
		
		self.send_reply(YMSGService.LogOn, YMSGStatus.Available, self.sess_id, logon_payload)
	
	def _get_oims(self, user: User) -> None:
		oims = self.backend.user_service.get_oim_batch(user)
		
		for oim in oims:
			oim_msg_dict = MultiDict([
				('31', b'6'),
				('32', b'6'),
				('1', arbitrary_encode(oim.from_user_id or misc.yahoo_id(oim.from_email))),
				('5', (self.yahoo_id or '').encode('utf-8')),
				('4', arbitrary_encode(oim.from_user_id or misc.yahoo_id(oim.from_email))),
				('15', str(int(oim.sent.timestamp())).encode('utf-8')),
				('14', arbitrary_encode(oim.message)),
				('97', b'1' if oim.utf8 else b'0'),
			]) # type: MultiDict[str, bytes]
			
			self.backend.user_service.delete_oim(user.uuid, oim.run_id)
			
			self.send_reply(YMSGService.Message, YMSGStatus.NotInOffice, self.sess_id, oim_msg_dict)
	
	def _verify_challenge_v1(self, yahoo_id: str, resp_6: bytes, resp_96: bytes) -> bool:
		from hashlib import md5
		
		chal = self.challenge
		if chal is None:
			return False
		
		uuid = yahoo_id_to_uuid(self.backend, yahoo_id)
		if uuid is None:
			return False
		
		# Retrieve Yahoo64-encoded MD5 hash of the user's password from the database
		# NOTE: The MD5 hash of the password is literally unsalted. Good grief, Yahoo!
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
	
	def _refresh_cookies(self) -> Tuple[str, str, str]:
		# Creates the cookies if they don't exist
		
		assert self.t_cookie_token is not None
		assert self.yahoo_id is not None
		
		auth_service = self.backend.auth_service
		
		timestamp = time.time()
		expiry = datetime.datetime.utcfromtimestamp(timestamp + 86400).strftime('%a, %d %b %Y %H:%M:%S GMT')
		
		y_cookie = Y_COOKIE_TEMPLATE.format(encodedname = _encode_yahoo_id(self.yahoo_id))
		t_cookie = T_COOKIE_TEMPLATE.format(token = self.t_cookie_token)
		
		auth_service.pop_token('ymsg/cookie', y_cookie)
		auth_service.pop_token('ymsg/cookie', t_cookie)
		
		y_cookie_new = auth_service.create_token('ymsg/cookie', self.yahoo_id, token = y_cookie, lifetime = 86400)
		t_cookie_new = auth_service.create_token('ymsg/cookie', self.bs, token = t_cookie, lifetime = 86400)
		
		return (y_cookie, t_cookie, expiry)

Y_COOKIE_TEMPLATE = 'v=1&n=&l={encodedname}&p=&r=&lg=&intl=&np='
T_COOKIE_TEMPLATE = 'z={token}&a=&sk={token}&ks={token}&kt=&ku=&d={token}'

YAHOO_HELPER_MSG = '"YahooHelper" was a bot initially developed by Yahoo! to help guide new users using Yahoo! Messenger for the first time and introduce them to its features. Escargot has no current plans to reimplement this bot.'

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

def add_contact_status_to_data(data: Any, status: UserStatus, contact: User, *, old_substatus: Substatus = Substatus.Offline, sess_id: Optional[int] = None) -> None:
	is_offlineish = status.is_offlineish()
	user_yahoo_id = misc.yahoo_id(contact.email)
	# `static var YMSG_FLD_SESSION_ID = 11;`
	# Yahoo! was weird sometimes :p
	if user_yahoo_id in PRE_SESSION_ID:
		key_11_val = binascii.hexlify(struct.pack('!I', PRE_SESSION_ID[user_yahoo_id])).decode().upper()
	elif sess_id is not None:
		key_11_val = binascii.hexlify(struct.pack('!I', sess_id)).decode().upper()
	else:
		if not (old_substatus.is_offlineish() and is_offlineish):
			key_11_val = contact.uuid[:8].upper()
		else:
			key_11_val = '0'
	
	data.add('7', user_yahoo_id)
	
	if is_offlineish or not status.message:
		data.add('10', str(int(YMSGStatus.Available if is_offlineish else YMSGStatus.FromSubstatus(status.substatus))).encode('utf-8'))
		data.add('11', key_11_val.encode('utf-8'))
	else:
		data.add('10', str(int(YMSGStatus.Custom)).encode('utf-8'))
		data.add('11', key_11_val.encode('utf-8'))
		data.add('19', arbitrary_encode(status.message))
		is_away_message = (status.substatus is not Substatus.Online)
		data.add('47', str(int(is_away_message)).encode('utf-8'))
	
	data.add('17', b'0')
	data.add('13', (b'0' if is_offlineish else b'1'))

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
			msg = 'Yahoo! Messenger will be down for maintenance in around ' + str(args[1]) + ' minute(s). Be sure to wrap up any conversations before this time period.'
		else:
			msg = message
		kvs = MultiDict([
			('14', msg.encode('utf-8')),
			('15', str(time.time()).encode('utf-8')),
		]) # type: # type: MultiDict[str, bytes]
		self.ctrl.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, kvs)
	
	def on_maintenance_boot(self) -> None:
		# No maintenance-specific booting packets known as of now. Use generic booting procedure.
		
		self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
		self.on_close()
	
	def on_presence_notification(self, bs_other: Optional[BackendSession], ctc: Contact, old_substatus: Substatus, on_contact_add: bool, *, trid: Optional[str] = None, update_status: bool = True, send_status_on_bl: bool = False, visible_notif: bool = True, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None, circle_user_bs: Optional[BackendSession] = None, circle_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		
		if on_contact_add: return
		
		if update_status:
			if not ctc.lists & Lst.FL: return
			if ctc.status.is_offlineish() and not old_substatus.is_offlineish():
				service = YMSGService.LogOff
			elif old_substatus.is_offlineish() and not ctc.status.is_offlineish():
				service = YMSGService.LogOn
			elif ctc.status.substatus is Substatus.Online:
				service = YMSGService.IsBack
			else:
				service = YMSGService.IsAway
			
			if not (ctc.status.is_offlineish() and old_substatus.is_offlineish()):
				yahoo_data = MultiDict() # type: MultiDict[str, Any]
				if service is not YMSGService.LogOff:
					yahoo_data.add('0', (self.ctrl.yahoo_id or '').encode('utf-8'))
				
				add_contact_status_to_data(yahoo_data, ctc.status, ctc.head, old_substatus = old_substatus, sess_id = sess_id)
				
				self.ctrl.send_reply(service, (YMSGStatus.Available if not visible_notif and service is YMSGService.LogOn else YMSGStatus.BRB), self.sess_id, yahoo_data)
	
	def on_presence_self_notification(self) -> None:
		pass
	
	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.OnVacation, self.sess_id, MultiDict([
			('1', misc.yahoo_id(bs.user.email).encode('utf-8')),
			('3', arbitrary_encode(contact_id or misc.yahoo_id(user_added.email))),
			('14', arbitrary_encode(message)),
		]))
	
	def msn_on_notify_ab(self, owner_cid: str, ab_last_modified: str) -> None:
		pass
	
	def msn_on_put_sent(self, payload: bytes, sender: User, *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
		pass
	
	#def ymsg_on_p2p_msg_request(self, yahoo_data: Dict[str, Any]) -> None:
	#	bs = self.bs
	#	assert bs is not None
	#	
	#	p2p_conn_dict = MultiDict([
	#		('5', yahoo_data.get('5')),
	#		('4', yahoo_data.get('1')),
	#	])
	#	
	#	if None not in (yahoo_data.get('2'),yahoo_data.get('13'),yahoo_data.get('12')):
	#		p2p_conn_dict.add('2', yahoo_data.get('2'))
	#		p2p_conn_dict.add('13', yahoo_data.get('13'))
	#		p2p_conn_dict.add('12', yahoo_data.get('12'))
	#	else:
	#		return
	#	
	#	p2p_conn_dict.add('49', yahoo_data.get('49'))
	#	if yahoo_data.get('60') is not None: p2p_conn_dict.add('60', yahoo_data.get('60'))
	#	if yahoo_data.get('61') is not None: p2p_conn_dict.add('60', yahoo_data.get('61'))
	#	
	#	self.ctrl.send_reply(YMSGService.PeerToPeer, YMSGStatus.BRB, self.sess_id, p2p_conn_dict)
	
	def ymsg_on_xfer_init(self, yahoo_data: Dict[str, Any]) -> None:
		for y in misc.build_ft_packet(self.bs, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		self.ctrl.send_reply(YMSGService.FileTransfer, YMSGStatus.BRB, self.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('5', arbitrary_encode(recipient)),
			('4', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('14', arbitrary_encode(message)),
		]))
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		for y in misc.build_http_ft_packet(self.bs, yahoo_id_sender, url_path, upload_time, message):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def on_chat_invite(self, chat: Chat, inviter: User, *, inviter_id: Optional[str] = None, invite_msg: str = '') -> None:
		if chat.front_data.get('ymsg_twoway_only'):
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
			('1', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('57', chat.ids['ymsg/conf'].encode('utf-8')),
			('50', arbitrary_encode(inviter_id or misc.yahoo_id(inviter.email))),
			('58', arbitrary_encode(invite_msg)),
		]) # type: MultiDict[str, bytes]
		
		roster = list(chat.get_roster_single())
		for cs in roster:
			if cs.user.uuid == inviter.uuid: continue
			conf_invite_dict.add('52', arbitrary_encode(cs.preferred_name or misc.yahoo_id(cs.user.email)))
			conf_invite_dict.add('53', arbitrary_encode(cs.preferred_name or misc.yahoo_id(cs.user.email)))
		
		conf_invite_dict.add('13', arbitrary_encode(chat.front_data.get('ymsg_voice_chat') or '0'))
		
		self.ctrl.send_reply(YMSGService.ConfAddInvite if len(roster) > 1 else YMSGService.ConfInvite, YMSGStatus.BRB, self.ctrl.sess_id, conf_invite_dict)
	
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
		
		contact_request_data = MultiDict([
<<<<<<< HEAD
			('1', misc.yahoo_id(user_me.email)),
			('3', adder_id or misc.yahoo_id(user.email)),
		]) # type: MultiDict[str, Any]
=======
			('1', misc.yahoo_id(user_me.email).encode('utf-8')),
			('3', misc.yahoo_id(adder_id or misc.yahoo_id(user.email))),
		]) # type: MultiDict[Any]
>>>>>>> ymsg: make parser more byte-friendly
		
		if message is not None:
			contact_request_data.add('14', arbitrary_encode(message.text))
			if message.yahoo_utf8 is not None:
				contact_request_data.add('97', arbitrary_encode(message.yahoo_utf8))
		
		contact_request_data.add('15', arbitrary_encode(str(time.time())))
		
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.NotAtHome, self.sess_id, contact_request_data)
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		if option is LoginOption.BootOthers:
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
	
	def on_close(self, keep_future: bool, idle: bool) -> None:
		if not keep_future: self.ctrl.chat_sessions.pop(self.cs.chat, None)
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool) -> None:
		if self.cs.chat.front_data.get('ymsg_twoway_only') or not first_pop:
			return
		self.ctrl.send_reply(YMSGService.ConfLogon, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('57', cs_other.chat.ids['ymsg/conf'].encode('utf-8')),
			('53', arbitrary_encode(cs_other.preferred_name or misc.yahoo_id(cs_other.user.email))),
		]))
	
	def on_participant_left(self, cs_other: ChatSession, idle: bool, last_pop: bool) -> None:
		if 'ymsg/conf' not in cs_other.chat.ids:
			# Yahoo only receives this event in "conferences"
			return
		if not last_pop:
			return
		self.ctrl.send_reply(YMSGService.ConfLogoff, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('57', cs_other.chat.ids['ymsg/conf'].encode('utf-8')),
			('56', cs_other.preferred_name or misc.yahoo_id(cs_other.user.email).encode('utf-8')),
		]))
	
	def on_invite_declined(self, invited_user: User, *, invited_id: Optional[str] = None, message: str = '') -> None:
		self.ctrl.send_reply(YMSGService.ConfDecline, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email).encode('utf-8')),
			('57', self.cs.chat.ids['ymsg/conf'].encode('utf-8')),
			('54', arbitrary_encode(invited_id or misc.yahoo_id(invited_user.email))),
			('14', arbitrary_encode(message)),
		]))
	
	def on_message(self, data: MessageData) -> None:
		bs = self.bs
		assert bs is not None
		
		sender = data.sender
		yahoo_data = messagedata_to_ymsg(data)
		
		if data.type in (MessageType.Chat,MessageType.Nudge):
			if self.cs.chat.front_data.get('ymsg_twoway_only'):
				message_to_dict = MultiDict([
					('5', yahoo_data.get('5') or misc.yahoo_id(bs.user.email).encode('utf-8')),
					('4', yahoo_data.get('1') or misc.yahoo_id(sender.email).encode('utf-8')),
					('14', yahoo_data.get('14') or arbitrary_encode(data.text or '')),
				])
				
				if yahoo_data.get('63') is not None:
					message_to_dict.add('63', yahoo_data.get('63'))
				
				if yahoo_data.get('64') is not None:
					message_to_dict.add('64', yahoo_data.get('64'))
				
				if yahoo_data.get('97') is not None:
					message_to_dict.add('97', yahoo_data.get('97'))
				
				self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_to_dict)
			else:
				if data.type is not MessageType.Nudge:
					conf_message_dict = MultiDict([
						('1', misc.yahoo_id(bs.user.email).encode('utf-8')),
						('57', self.cs.chat.ids['ymsg/conf'].encode('utf-8')),
						('3', yahoo_data.get('1') or misc.yahoo_id(sender.email).encode('utf-8')),
						('14', yahoo_data.get('14') or arbitrary_encode(data.text or '')),
					])
					
					if yahoo_data.get('97') is not None:
						conf_message_dict.add('97', yahoo_data.get('97'))
					
					self.ctrl.send_reply(YMSGService.ConfMsg, YMSGStatus.BRB, self.ctrl.sess_id, conf_message_dict)
		elif data.type in (MessageType.Typing,MessageType.TypingDone) and self.cs.chat.front_data.get('ymsg_twoway_only'):
			self.ctrl.send_reply(YMSGService.Notify, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
				('5', yahoo_data.get('5') or misc.yahoo_id(bs.user.email).encode('utf-8')),
				('4', yahoo_data.get('1') or misc.yahoo_id(sender.email).encode('utf-8')),
				('49', b'TYPING'),
				('14', yahoo_data.get('14') or arbitrary_encode(data.text or ' ')),
				('13', yahoo_data.get('13') or (b'0' if data.type is MessageType.TypingDone else b'1'))
			]))
		elif data.type is MessageType.Webcam:
			kvs = MultiDict([
				('5', yahoo_data.get('5') or misc.yahoo_id(bs.user.email).encode('utf-8')),
				('4', yahoo_data.get('1') or misc.yahoo_id(sender.email).encode('utf-8')),
				('49', b'WEBCAMINVITE'),
				('14', yahoo_data.get('14') or arbitrary_encode(data.text or ' ')),
			]) # type: MultiDict[str, Any]
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

def messagedata_from_ymsg(sender: User, data: Dict[str, Any], *, notify_type: Optional[bytes] = None, typing_flag: Optional[str] = None) -> MessageData:
	text = arbitrary_decode(data.get('14') or b'')
	
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

def messagedata_to_ymsg(data: MessageData) -> Dict[str, Any]:
	if 'ymsg' not in data.front_cache:
		data.front_cache['ymsg'] = MultiDict([
			('14', (b'<ding>' if data.type is MessageType.Nudge else arbitrary_encode(data.text or ''))),
			('63', b';0'),
			('64', b'0'),
			('97', b'1'),
		])
	return data.front_cache['ymsg']

def me_status_update(bs: BackendSession, status_new: YMSGStatus, *, message: str = '', send_notif_to_self: bool = True, is_away_message: bool = False) -> None:
	bs.front_data['ymsg_status'] = status_new
	if status_new is YMSGStatus.Custom:
		substatus = (Substatus.Busy if is_away_message else Substatus.Online)
	else:
		substatus = YMSGStatus.ToSubstatus(status_new)
	bs.me_update({
		'message': message,
		'message_temp': True,
		'substatus': substatus,
		'send_notif_to_self': send_notif_to_self,
	})

def generate_challenge_v1() -> bytes:
	from uuid import uuid4
	
	# Yahoo64-encode the raw 16 bytes of a UUID
	return Y64.Y64Encode(uuid4().bytes)
