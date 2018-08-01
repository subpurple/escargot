from typing import Optional, Dict, Any, List, Iterable, Set, Tuple
import secrets
import datetime
from multidict import MultiDict
import asyncio
import time
import binascii

from util.misc import Logger

from core import event, error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import Substatus, Lst, User, Contact, Group, TextWithData, MessageData, MessageType, UserStatus, LoginOption
from core.client import Client
from core.user import UserService
from core.auth import AuthService

from .ymsg_ctrl import YMSGCtrlBase
from .misc import YMSGService, YMSGStatus, yahoo_id_to_uuid
from . import misc, Y64

# "Pre" because it's needed before BackendSession is created.
PRE_SESSION_ID: Dict[str, int] = {}

class YMSGCtrlPager(YMSGCtrlBase):
	__slots__ = ('backend', 'dialect', 'yahoo_id', 'sess_id', 'challenge', 't_cookie_token', 'bs', 'activated_alias_bses', 'chat_sessions', 'client')
	
	backend: Backend
	dialect: int
	yahoo_id: str
	sess_id: int
	challenge: Optional[str]
	t_cookie_token: Optional[str]
	bs: Optional[BackendSession]
	activated_alias_bses: Dict[str, BackendSession]
	chat_sessions: Dict[Chat, ChatSession]
	client: Client
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.yahoo_id = ''
		self.sess_id = 0
		self.challenge = None
		self.t_cookie_token = None
		self.bs = None
		self.activated_alias_bses = {}
		
		self.chat_sessions = {}
		self.client = Client('yahoo', '?', via)
	
	def _on_close(self) -> None:
		if self.yahoo_id:
			PRE_SESSION_ID.pop(self.yahoo_id, None)
		
		if self.bs:
			self.bs.close()
	
	# State = Auth
	
	def _y_004c(self, *args) -> None:
		# SERVICE_HANDSHAKE (0x4c); acknowledgement of the server
		
		self.client = Client('yahoo', 'YMSG' + str(args[0]), self.client.via)
		self.dialect = int(args[0])
		self.send_reply(YMSGService.Handshake, YMSGStatus.BRB, 0, None)
	
	def _y_0057(self, *args) -> None:
		# SERVICE_AUTH (0x57); send a challenge string for the client to craft two response strings with
		
		arg1 = args[4].get('1')
		assert isinstance(arg1, str)
		self.yahoo_id = arg1
		
		# TODO: IDK remove the `self._is_yahoo_acc` bit I guess if needed. This is just to deliver the specific "non-existent user" error to the
		# client. Plus, there's no way to check if a `User` is an MSN user, so kinda dumb to check if someone's a Yahoo! user. =p
		
		if not self._is_yahoo_acc(yahoo_id_to_uuid(self.backend, self.yahoo_id)):
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, 0, MultiDict([
				('66', int(YMSGStatus.NotAtHome))
			]))
			return
		
		if self.yahoo_id in PRE_SESSION_ID:
			self.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
			self.close()
			return
		self.sess_id = secrets.randbelow(4294967294) + 1
		PRE_SESSION_ID[self.yahoo_id] = self.sess_id
		
		auth_dict = MultiDict([
			('1', self.yahoo_id),
		])
		
		if 9 <= self.dialect <= 10:
			self.challenge = generate_challenge_v1()
			auth_dict.add('94', self.challenge)
		elif self.dialect <= 11:
			# Implement V2 challenge string generation later
			auth_dict.add('94', '')
			auth_dict.add('13', 1)
		
		self.send_reply(YMSGService.Auth, YMSGStatus.BRB, self.sess_id, auth_dict)
	
	def _y_0054(self, *args) -> None:
		# SERVICE_AUTHRESP (0x54); verify response strings for successful authentication
		
		status = args[2]
		if status is YMSGStatus.WebLogin:
			status = YMSGStatus.Available
		
		resp_6 = args[4].get('6')
		resp_96 = args[4].get('96')
		
		version = args[4].get('135')
		self.client = Client('yahoo', version, self.client.via)
		
		assert self.yahoo_id
		
		# TODO: Dialect 11 not supported yet?
		assert 9 <= self.dialect <= 10
		
		assert self.challenge is not None
		is_resp_correct = self._verify_challenge_v1(resp_6, resp_96)
		if is_resp_correct:
			uuid = yahoo_id_to_uuid(self.backend, self.yahoo_id)
			if uuid is None:
				is_resp_correct = False
			else:
				bs = self.backend.login(uuid, self.client, BackendEventHandler(self.backend.loop, self), LoginOption.BootOthers)
				if bs is None:
					is_resp_correct = False
				else:
					self.bs = bs
					self._util_authresp_final(status)
		
		if not is_resp_correct:
			self.send_reply(YMSGService.AuthResp, YMSGStatus.LoginError, self.sess_id, MultiDict([
				('66', int(YMSGStatus.Bad))
			]))
	
	def _is_yahoo_acc(self, uuid: Optional[str]) -> bool:
		if uuid is None: return False
		
		if self.backend.user_service.check_user_front_type(uuid, 'ymsg'): return True
		return False
	
	def _util_authresp_final(self, status: YMSGStatus) -> None:
		bs = self.bs
		assert bs is not None
		
		self.t_cookie_token = AuthService.GenTokenStr()
		
		me_status_update(bs, status)
		
		bs.front_data['ymsg_private_chats'] = {}
		bs.front_data['ymsg_alias'] = False
		
		self._get_oims(self.yahoo_id)
		
		self._update_buddy_list(after_login = True)
		
		if self.dialect >= 10:
			self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, MultiDict([
				('143', 60),
				('144', 13)
			]))
		
		if self.backend.notify_maintenance:
			bs.evt.on_system_message(None, self.backend.maintenance_mins)
	
	# State = Live
	
	def _y_0004(self, *args) -> None:
		# SERVICE_ISBACK (0x04); notify contacts of online presence
		
		bs = self.bs
		assert bs is not None
		
		new_status = YMSGStatus(int(args[2]))
		
		me_status_update(bs, new_status)
		for _, alias_bs in self.activated_alias_bses.items():
			me_status_update(alias_bs, new_status)
	
	def _y_0003(self, *args) -> None:
		# SERVICE_ISAWAY (0x03); notify contacts of FYI idle presence
		
		bs = self.bs
		assert bs is not None
		
		new_status = YMSGStatus(int(args[4].get('10')))
		message = args[4].get('19') or ''
		is_away_message = (args[4].get('47') == '1')
		me_status_update(bs, new_status, message = message, is_away_message = is_away_message)
		for _, alias_bs in self.activated_alias_bses.items():
			me_status_update(alias_bs, new_status, message = message, is_away_message = is_away_message)
	
	def _y_0012(self, *args) -> None:
		# SERVICE_PINGCONFIGURATION (0x12); set the "ticks" and "tocks" of a ping sent
		
		self.send_reply(YMSGService.PingConfiguration, YMSGStatus.Available, self.sess_id, MultiDict([
			('143', 60),
			('144', 13)
		]))
	
	def _y_0016(self, *args) -> None:
		# SERVICE_PASSTHROUGH2 (0x16); collects OS version, processor, and time zone
		#
		# 1: YahooId
		# 25: unknown ('C=0[0x01]F=1,P=0,C=0,H=0,W=0,B=0,O=0,G=0[0x01]M=0,P=0,C=0,S=0,L=3,D=1,N=0,G=0,F=0,T=0')
		# 146: Base64-encoded string of host OS (e.g.: 'V2luZG93cyAyMDAwLCBTZXJ2aWNlIFBhY2sgNA==' = 'Windows 2000, Service Pack 4')
		# 145: Base64-encoded string of processor type (e.g.: 'SW50ZWwgUGVudGl1bSBQcm8gb3IgUGVudGl1bQ==' = 'Intel Pentium Pro or Pentium')
		# 147: Base64-encoded string of time zone (e.g.: 'RWFzdGVybiBTdGFuZGFyZCBUaW1l' = 'Eastern Standard Time')
		
		return
	
	def _y_0015(self, *args) -> None:
		# SERVICE_SKINNAME (0x15); used for IMVironments
		# Also happens when enabling/disabling Yahoo Helper.
		return
	
	def _y_0083(self, *args) -> None:
		# SERVICE_FRIENDADD (0x83); add a friend to your contact list
		
		contact_yahoo_id = args[4].get('7')
		message = args[4].get('14')
		buddy_group = args[4].get('65')
		utf8 = args[4].get('97')
		
		group = None
		
		add_request_response = MultiDict([
			('1', self.yahoo_id),
			('7', contact_yahoo_id),
			('65', buddy_group)
		])
		
		# Yahoo! Messenger has a function that lets you add people by email address (a.k.a. stripping the "@domain.tld" part of the address and
		# filling that out in the "Yahoo! ID" section of the contact add dialog). Treat as is.
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id)
		if contact_uuid is None:
			add_request_response.add('66', 3)
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		groups = detail.groups
		
		cs = list(contacts.values())
		cs_fl = [c for c in cs if c.lists & Lst.FL]
		
		if len(cs_fl) >= 100:
			add_request_response.add('66', 6)
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			return
		
		contact = contacts.get(contact_uuid)
		if contact is not None and contact.lists & Lst.FL:
			for grp_id in contact.groups:
				if groups[grp_id].name == buddy_group:
					add_request_response.add('66', 2)
					self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
					return
		
		for grp in groups.values():
			if grp.name == buddy_group:
				group = grp
				break
		
		if group is None:
			group = bs.me_group_add(buddy_group)
			action_group_move = False
		else:
			action_group_move = True
		
		ctc_head = self.backend._load_user_record(contact_uuid)
		assert ctc_head is not None
		
		if not ctc_head.status.is_offlineish():
			contact_struct = MultiDict([
				('0', self.yahoo_id),
			])
			add_contact_status_to_data(contact_struct, ctc_head.status, ctc_head)
		else:
			contact_struct = None
		
		self.send_reply(YMSGService.ContactNew, YMSGStatus.BRB, self.sess_id, contact_struct)
		
		if not contact or not contact.lists & Lst.FL:
			add_request_response.add('66', 0)
			self.send_reply(YMSGService.FriendAdd, YMSGStatus.BRB, self.sess_id, add_request_response)
			
			contact = bs.me_contact_add(ctc_head.uuid, Lst.FL, message = (TextWithData(message, utf8) if message is not None else None), send_notif_on_AL = True, needs_notify = True)[0]
		try:
			if action_group_move:
				for grp_id in contact.groups.copy():
					bs.me_group_contact_remove(grp_id, contact_uuid)
			
			bs.me_group_contact_add(group.id, contact_uuid)
			
			if action_group_move: self._update_buddy_list()
		except error.ContactAlreadyOnList:
			# Ignore, because this condition was checked earlier, so the only way this
			# can happen is if the the contact list gets in an inconsistent state.
			# (I.e. contact is not on FL, but still part of groups.)
			pass
	
	def _y_0086(self, *args) -> None:
		# SERVICE_CONTACTDENY (0x86); deny a contact request
		
		adder_to_deny = args[4].get('7')
		deny_message = args[4].get('14')
		
		adder_uuid = yahoo_id_to_uuid(self.backend, adder_to_deny)
		assert adder_uuid is not None
		bs = self.bs
		assert bs is not None
		bs.me_contact_deny(adder_uuid, deny_message)
	
	def _y_0089(self, *args) -> None:
		# SERVICE_GROUPRENAME (0x89); rename a contact group
		
		old_group_name = args[4].get('65')
		new_group_name = args[4].get('67')
		bs = self.bs
		assert bs is not None
		
		bs.me_group_edit(old_group_name, new_group_name)
		
		self._update_buddy_list()
	
	def _y_0084(self, *args) -> None:
		# SERVICE_FRIENDREMOVE (0x84); remove a buddy from your list
		
		contact_id = args[4].get('7')
		buddy_group = args[4].get('65')
		
		remove_buddy_response = MultiDict([
			('1', self.yahoo_id),
			('7', contact_id),
			('65', buddy_group)
		])
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_id)
		if contact_uuid is None:
			remove_buddy_response.add('66', 3)
			self.send_reply(YMSGService.FriendRemove, YMSGStatus.BRB, self.sess_id, remove_buddy_response)
			return
		
		bs.me_contact_remove(contact_uuid, Lst.FL)
		
		self._update_buddy_list()
	
	def _y_0085(self, *args) -> None:
		# SERVICE_IGNORE (0x85); add/remove someone from your ignore list
		
		ignored_yahoo_id = args[4].get('7')
		ignore_mode = args[4].get('13')
		
		ignore_reply_response = MultiDict([
			('0', self.yahoo_id),
			('7', ignored_yahoo_id),
			('13', ignore_mode)
		])
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		contacts = detail.contacts
		
		ignored_uuid = yahoo_id_to_uuid(self.backend, ignored_yahoo_id)
		if ignored_uuid is None:
			ignore_reply_response.add('66', 3)
			self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
			return
		
		if int(ignore_mode) == 1:
			contact = contacts.get(ignored_uuid)
			if contact is not None:
				if not contact.groups and (contact.lists & Lst.BL):
					ignore_reply_response.add('66', 2)
					self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
					return
			bs.me_contact_add(ignored_uuid, Lst.BL)
		elif int(ignore_mode) == 2:
			bs.me_contact_remove(ignored_uuid, Lst.BL)
		
		self.send_reply(YMSGService.AddIgnore, YMSGStatus.BRB, self.sess_id, None)
		ignore_reply_response.add('66', 0)
		self.send_reply(YMSGService.Ignore, YMSGStatus.BRB, self.sess_id, ignore_reply_response)
	
	def _y_000a(self, *args) -> None:
		# SERVICE_USERSTAT (0x0a); synchronize logged on user's status
		
		if self.yahoo_id != args[4].get('0'):
			return
		
		bs = self.bs
		assert bs is not None
		
		self.send_reply(YMSGService.UserStat, bs.front_data.get('ymsg_status') or YMSGStatus.Available, self.sess_id, None)
		self._update_buddy_list()
	
	def _y_0055(self, *args) -> None:
		# SERVICE_LIST (0x55); send a user's buddy list
		
		self._update_buddy_list()
	
	def _y_008a(self, *args) -> None:
		# SERVICE_PING (0x8a); send a response ping after the client pings
		
		self.send_reply(YMSGService.Ping, YMSGStatus.Available, self.sess_id, MultiDict([
			('1', self.yahoo_id),
		]))
	
	def _y_0008(self, *args) -> None:
		# SERVICE_IDDEACTIVATE (0x08); deactivate an alias
		
		alias = args[4].get('3')
		
		self._deactivate_alias(alias)
		
		self.send_reply(YMSGService.IDDeactivate, YMSGStatus.BRB, self.sess_id, MultiDict([
			('3', alias),
		]))
	
	def _y_0007(self, *args) -> None:
		# SERVICE_IDACTIVATE (0x07); activate an alias
		
		alias = args[4].get('3')
		
		self._activate_alias(alias)
		
		self.send_reply(YMSGService.IDActivate, YMSGStatus.BRB, self.sess_id, MultiDict([
			('3', alias),
		]))
	
	def _y_004f(self, *args) -> None:
		# SERVICE_PEERTOPEER (0x4f); see if P2P messaging is possible
		
		yid = args[4].get('1')
		yid_from = args[4].get('4')
		if self.yahoo_id not in (yid,yid_from): return
		
		p2p_to_id = args[4].get('5')
		contact_uuid = yahoo_id_to_uuid(self.backend, p2p_to_id)
		if contact_uuid is None or args[4].get('49') != 'PEERTOPEER':
			return
		
		bs = (self.bs if yid not in self.activated_alias_bses else self.activated_alias_bses[yid])
		assert bs is not None
		
		for bs_other in bs.backend._sc.iter_sessions():
			if bs_other.user.uuid == contact_uuid:
				bs_other.evt.ymsg_on_p2p_msg_request(bs.user, args[4])
	
	def _y_004b(self, *args) -> None:
		# SERVICE_NOTIFY (0x4b); notify a contact of an action (typing, games, etc.)
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		notify_type = yahoo_data.get('49') # typing, games, etc.
		contact_yahoo_id = yahoo_data.get('5')
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id)
		if contact_uuid is None:
			return
		
		cs, _ = self._get_private_chat_with(yahoo_id, contact_uuid)
		if cs is not None:
			cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data, notify_type = notify_type))
	
	def _y_0006(self, *args) -> None:
		# SERVICE_MESSAGE (0x06); send a message to a user
		
		self._message_common(args[4], args[4].get('5'), args[4].get('1'))
	
	def _y_0017(self, *args) -> None:
		# SERVICE_MASSMESSAGE (0x17); send a message to multiple users
		
		contact_yahoo_ids = args[4].getall('5')
		if contact_yahoo_ids:
			for yahoo_id in contact_yahoo_ids:
				self._message_common(args[4], yahoo_id, args[4].get('1'))
	
	def _y_004d(self, *args) -> None:
		# SERVICE_P2PFILEXFER (0x4d); initiate P2P file transfer. Due to this service being present in 3rd-party libraries; we can implement it here
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('4')
		
		bs = (self.bs if yahoo_id not in self.activated_alias_bses else self.activated_alias_bses[yahoo_id])
		assert bs is not None
		
		contact_uuid = yahoo_id_to_uuid(self.backend, yahoo_data.get('5'))
		if contact_uuid is None:
			return
		
		for bs_other in bs.backend._sc.iter_sessions():
			if bs_other.user.uuid == contact_uuid:
				bs_other.evt.ymsg_on_xfer_init(bs.user, yahoo_data)
	
	def _y_0018(self, *args) -> None:
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
			if conf_user_uuid is None:
				continue
			cs.invite(self.backend._load_user_record(conf_user_uuid), invite_msg = invite_msg)
	
	def _y_001c(self, *args) -> None:
		# SERVICE_CONFADDINVITE (0x1c); send a conference invite to an existing conference to one or more people
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		conf_new_roster_str = yahoo_data.get('51')
		if conf_new_roster_str is None:
			return
		conf_new_roster = conf_new_roster_str.split(',')
		conf_roster = yahoo_data.getall('52', None)
		if conf_roster is None:
			conf_roster = yahoo_data.getall('53', None)
			if conf_roster is None:
				conf_roster = []
		conf_id = yahoo_data.get('57')
		invite_msg = yahoo_data.get('58')
		voice_chat = yahoo_data.get('13')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		
		chat.front_data['ymsg_voice_chat'] = voice_chat
		
		for conf_user_yahoo_id in conf_new_roster:
			conf_user_uuid = yahoo_id_to_uuid(self.backend, conf_user_yahoo_id)
			if conf_user_uuid is None:
				continue
			cs.invite(self.backend._load_user_record(conf_user_uuid), invite_msg = invite_msg)
	
	def _y_0019(self, *args) -> None:
		# SERVICE_CONFLOGON (0x19); request for me to join a conference
		
		#inviter_ids = args[4].getall('3', None)
		#if inviter_ids is None:
		#	return
		
		yahoo_id = args[4].get('1')
		conf_id = args[4].get('57')
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat, create = True)
		assert cs is not None
	
	def _y_001a(self, *args) -> None:
		# SERVICE_CONFDECLINE (0x1a); decline a request to join a conference
		
		yahoo_id = args[4].get('1')
		
		bs = (self.bs if yahoo_id not in self.activated_alias_bses else self.activated_alias_bses[yahoo_id])
		assert bs is not None
		
		inviter_ids = args[4].getall('3', None)
		if inviter_ids is None:
			return
		conf_id = args[4].get('57')
		deny_msg = args[4].get('14')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		
		for cs in chat.get_roster():
			if misc.yahoo_id(cs.user.email) not in inviter_ids:
				continue
			cs.evt.on_invite_declined(bs.user, message = deny_msg)
	
	def _y_001d(self, *args) -> None:
		# SERVICE_CONFMSG (0x1d); send a message in a conference
		
		#conf_user_ids = args[4].getall('53', None)
		#if conf_user_ids is None:
		#	return
		
		yahoo_data = args[4]
		yahoo_id = yahoo_data.get('1')
		conf_id = yahoo_data.get('57')
		
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		assert chat is not None
		cs = self._get_chat_session(yahoo_id, chat)
		assert cs is not None
		cs.send_message_to_everyone(messagedata_from_ymsg(cs.user, yahoo_data))
	
	def _y_001b(self, *args) -> None:
		# SERVICE_CONFLOGOFF (0x1b); leave a conference
		
		#conf_roster = args[4].getall('3', None)
		#if conf_roster is None:
		#	return
		
		yahoo_id = args[4].get('1')
		conf_id = args[4].get('57')
		chat = self._get_chat_by_id('ymsg/conf', conf_id)
		if chat is None:
			return
		cs = self._get_chat_session(yahoo_id, chat)
		if cs is not None:
			cs.close(keep_future = True)
	
	# Other functions
	
	def _message_common(self, yahoo_data: Dict[str, Any], contact_yahoo_id: str, yahoo_id: str) -> None:
		if contact_yahoo_id == 'YahooHelper':
			yhlper_msg_dict = MultiDict([
				('5', self.yahoo_id),
				('4', 'YahooHelper'),
				('14', YAHOO_HELPER_MSG),
			])
			
			if yahoo_data.get('63') is not None:
				yhlper_msg_dict.add('63', yahoo_data.get('63'))
			
			if yahoo_data.get('64') is not None:
				yhlper_msg_dict.add('64', yahoo_data.get('64'))
			
			yhlper_msg_dict.add('97', 1)
			
			self.send_reply(YMSGService.Message, YMSGStatus.BRB, self.sess_id, yhlper_msg_dict)
			return
		
		contact_uuid = yahoo_id_to_uuid(self.backend, contact_yahoo_id)
		if contact_uuid is None:
			return
		
		cs, evt = self._get_private_chat_with(yahoo_id, contact_uuid)
		if None not in (cs, evt):
			evt._send_when_user_joins(contact_uuid, messagedata_from_ymsg(cs.user, yahoo_data))
		else:
			md = messagedata_from_ymsg(self.backend._load_user_record(contact_uuid), yahoo_data)
			if md.type is MessageType.Chat:
				self.backend.user_service.yahoo_save_oim(
					md.text, (bool(int(md.front_cache['ymsg'].get('97'))) if md.front_cache['ymsg'].get('97') is not None else None),
					yahoo_id, self.yahoo_id, contact_yahoo_id,
					datetime.datetime.utcnow(),
				)
	
	def _get_private_chat_with(self, yahoo_id: str, other_user_uuid: str) -> Tuple[ChatSession, 'ChatEventHandler']:
		bs = (self.bs if yahoo_id not in self.activated_alias_bses else self.activated_alias_bses.get(yahoo_id))
		assert bs is not None
		
		other_user = self.backend._load_user_record(other_user_uuid)
		if other_user_uuid not in bs.front_data['ymsg_private_chats'] and other_user.status.substatus is not Substatus.Offline:
			chat = self.backend.chat_create()
			chat.front_data['ymsg_twoway_only'] = True
			
			# `user` joins
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt)
			bs.front_data['ymsg_private_chats'][other_user_uuid] = (cs, evt)
			cs.invite(other_user)
		return (bs.front_data['ymsg_private_chats'].get(other_user_uuid) if other_user.status.substatus is not Substatus.Offline else (None, None))
	
	def _get_chat_by_id(self, scope: str, id: str, *, create: bool = False) -> Optional[Chat]:
		chat = self.backend.chat_get(scope, id)
		if chat is None and create:
			chat = self.backend.chat_create()
			chat.add_id(scope, id)
		return chat
	
	def _get_chat_session(self, yahoo_id: str, chat: Chat, *, create: bool = False) -> Optional[ChatSession]:
		bs = (self.bs if yahoo_id not in self.activated_alias_bses else self.activated_alias_bses.get(yahoo_id))
		assert bs is not None
		
		cs = self.chat_sessions.get(chat)
		if cs is None and create:
			evt = ChatEventHandler(self.backend.loop, self, bs)
			cs = chat.join('yahoo', bs, evt)
			self.chat_sessions[chat] = cs
			chat.send_participant_joined(cs)
		return cs
	
	def _update_buddy_list(self, after_login: bool = False) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		groups = detail.groups
		
		cs = list(contacts.values())
		cs_fl = [c for c in cs if c.lists & Lst.FL]
		
		contact_group_list = []
		for grp in groups.values():
			contact_list = []
			for c in cs_fl:
				if grp.id in c.groups:
					contact_list.append(misc.yahoo_id(c.head.email))
			if contact_list:
				contact_group_list.append(grp.name + ':' + ','.join(contact_list) + '\n')
		# Handle contacts that aren't part of any groups
		# Since Yahoo! Messenger by design requires you to add a contact to a group, remove when code is pushed to `master` branch
		contact_list = [misc.yahoo_id(c.head.email) for c in cs_fl if not c.groups]
		if contact_list:
			contact_group_list.append('(No Group):' + ','.join(contact_list) + '\n')
		
		ignore_list = []
		for c in cs:
			if c.lists & Lst.BL:
				ignore_list.append(misc.yahoo_id(c.head.email))
		
		id_list = [self.yahoo_id]
		aliases = self.backend.user_service.yahoo_get_aliases(user.uuid)
		for alias in aliases: id_list.append(alias.alias_yid)
		
		(y_cookie, t_cookie, cookie_expiry) = self._refresh_cookies()
		
		self.send_reply(YMSGService.List, YMSGStatus.Available, self.sess_id, MultiDict([
			('87', ''.join(contact_group_list)),
			('88', ','.join(ignore_list)),
			('89', ','.join(id_list)),
			('59', '{}\t{}; expires={}; path=/; domain=.yahoo.com'.format('Y', y_cookie, cookie_expiry)),
			('59', '{}\t{}; expires={}; path=/; domain=.yahoo.com'.format('T', t_cookie, cookie_expiry)),
			('59', 'C\tmg=1'),
			('3', self.yahoo_id),
			('90', '1'),
			('100', '0'),
			('101', ''),
			('102', ''),
			('93', '86400')
		]))
		
		logon_payload = MultiDict([
			('0', self.yahoo_id),
			('1', self.yahoo_id),
			('8', len(cs_fl))
		])
		
		for c in cs_fl:
			add_contact_status_to_data(logon_payload, c.status, c.head)
		
		if after_login:
			for alias in aliases:
				if alias.is_activated:
					self.send_reply(YMSGService.IDActivate, YMSGStatus.BRB, self.sess_id, MultiDict([
						('3', alias.alias_yid),
					]))
					
					self._activate_alias(alias.alias_yid)
				else:
					self.send_reply(YMSGService.IDDeactivate, YMSGStatus.BRB, self.sess_id, MultiDict([
						('3', alias.alias_yid),
					]))
		
		self.send_reply(YMSGService.LogOn, YMSGStatus.Available, self.sess_id, logon_payload)
	
	def _get_oims(self, yahoo_id: str) -> None:
		oims = self.backend.user_service.yahoo_get_oim_message_by_recipient(yahoo_id)
		
		for oim in oims:
			oim_msg_dict = MultiDict([
				('31', 6),
				('32', 6),
				('1', oim.from_id),
				('5', oim.recipient_id),
				('4', oim.from_id),
				('15', int(oim.sent.timestamp())),
				('14', oim.message),
			])
			
			if oim.utf8_kv is not None:
				oim_msg_dict.add('97', int(oim.utf8_kv))
			
			self.send_reply(YMSGService.Message, YMSGStatus.NotInOffice, self.sess_id, oim_msg_dict)
	
	def _activate_alias(self, alias: str) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		alias_bs = self.backend.login(yahoo_id_to_uuid(self.backend, alias), self.client, BackendEventHandler(self.backend.loop, self), LoginOption.Duplicate)
		assert alias_bs is not None
		alias_bs.front_data['ymsg_private_chats'] = {}
		alias_bs.front_data['ymsg_alias'] = True
		self.backend.user_service.yahoo_set_alias_activated_status(alias, True)
		self.activated_alias_bses[alias] = alias_bs
		me_status_update(alias_bs, YMSGStatus.FromSubstatus(user.status.substatus))
		self._get_oims(alias)
	
	def _deactivate_alias(self, alias: str) -> None:
		alias_bs = self.activated_alias_bses.pop(alias, None)
		assert alias_bs is not None
		
		alias_bs.close(passthrough = True)
		self.backend.user_service.yahoo_set_alias_activated_status(alias, False)
	
	def _verify_challenge_v1(self, resp_6: str, resp_96: str) -> bool:
		from hashlib import md5
		
		chal = self.challenge
		if chal is None:
			return False
		
		yahoo_id = self.yahoo_id
		if yahoo_id is None:
			return False
		
		uuid = yahoo_id_to_uuid(self.backend, yahoo_id)
		if uuid is None:
			return False
		
		# Retrieve Yahoo64-encoded MD5 hash of the user's password from the database
		# NOTE: The MD5 hash of the password is literally unsalted. Good grief, Yahoo!
		pass_md5 = Y64.Y64Encode(self.backend.user_service.yahoo_get_md5_password(uuid) or b'')
		# Retrieve MD5-crypt(3)'d hash of the user's password from the database
		pass_md5crypt = Y64.Y64Encode(md5(self.backend.user_service.yahoo_get_md5crypt_password(uuid) or b'').digest())
		
		seed_val = (ord(chal[15]) % 8) % 5
		
		if seed_val == 0:
			checksum = chal[ord(chal[7]) % 16]
			hash_p = checksum + pass_md5 + yahoo_id + chal
			hash_c = checksum + pass_md5crypt + yahoo_id + chal
		elif seed_val == 1:
			checksum = chal[ord(chal[9]) % 16]
			hash_p = checksum + yahoo_id + chal + pass_md5
			hash_c = checksum + yahoo_id + chal + pass_md5crypt
		elif seed_val == 2:
			checksum = chal[ord(chal[15]) % 16]
			hash_p = checksum + chal + pass_md5 + yahoo_id
			hash_c = checksum + chal + pass_md5crypt + yahoo_id
		elif seed_val == 3:
			checksum = chal[ord(chal[1]) % 16]
			hash_p = checksum + yahoo_id + pass_md5 + chal
			hash_c = checksum + yahoo_id + pass_md5crypt + chal
		elif seed_val == 4:
			checksum = chal[ord(chal[3]) % 16]
			hash_p = checksum + pass_md5 + chal + yahoo_id
			hash_c = checksum + pass_md5crypt + chal + yahoo_id
		
		resp_6_server = Y64.Y64Encode(md5(hash_p.encode()).digest())
		resp_96_server = Y64.Y64Encode(md5(hash_c.encode()).digest())
		
		return resp_6 == resp_6_server and resp_96 == resp_96_server
	
	def _refresh_cookies(self) -> Tuple[str, str, str]:
		# Creates the cookies if they don't exist
		
		assert self.t_cookie_token is not None
		
		auth_service = self.backend.auth_service
		
		timestamp = int(time.time())
		expiry = datetime.datetime.utcfromtimestamp(timestamp + 86400).strftime('%a, %d %b %Y %H:%M:%S GMT')
		
		y_cookie = Y_COOKIE_TEMPLATE.format(encodedname = _encode_yahoo_id(self.yahoo_id))
		t_cookie = T_COOKIE_TEMPLATE.format(token = self.t_cookie_token)
		
		auth_service.pop_token('ymsg/cookie', y_cookie)
		auth_service.pop_token('ymsg/cookie', t_cookie)
		
		auth_service.create_token('ymsg/cookie', self.yahoo_id, token = y_cookie, lifetime = 86400)
		auth_service.create_token('ymsg/cookie', self.bs, token = t_cookie, lifetime = 86400)
		
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

def add_contact_status_to_data(data: Any, status: UserStatus, contact: User) -> None:
	is_offlineish = status.is_offlineish()
	user_yahoo_id = misc.yahoo_id(contact.email)
	key_11_val = contact.uuid[:8].upper()
	
	data.add('7', user_yahoo_id)
	
	if is_offlineish or not status.message:
		data.add('10', int(YMSGStatus.Available if is_offlineish else YMSGStatus.FromSubstatus(status.substatus)))
		data.add('11', key_11_val)
	else:
		data.add('10', int(YMSGStatus.Custom))
		data.add('11', key_11_val)
		data.add('19', status.message)
		is_away_message = (status.substatus is not Substatus.Online)
		data.add('47', int(is_away_message))
	
	data.add('17', 0)
	data.add('13', (0 if is_offlineish else 1))

def user_in_contact_list(user_me: User, user: User, backend: Backend) -> Tuple[bool, Contact]:
	# If the specified user is on the other user's contact list, whether vice versa applies or not, that should
	# meet the criteria to say that that person's on their contact list.
	detail = user_me.detail
	assert detail is not None
	
	ctc = detail.contacts.get(user.uuid)
	if ctc is None or not ctc.lists & Lst.FL: return (False,None)
	return (True,ctc)

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
		
		self.ctrl.send_reply(YMSGService.SystemMessage, YMSGStatus.BRB, self.sess_id, MultiDict([
			('14', msg),
			('15', time.time()),
		]))
	
	def on_maintenance_boot(self) -> None:
		# No maintenance-specific booting packets known as of now. Use generic booting procedure.
		
		self.ctrl.send_reply(YMSGService.LogOff, YMSGStatus.Available, 0, None)
		self.on_close()
	
	def on_presence_notification(self, user: User, old_substatus: Substatus, on_contact_add: bool) -> None:
		bs = self.bs
		assert bs is not None
		
		if on_contact_add: return
		
		is_contact = user_in_contact_list(bs.user, user, self.ctrl.backend)
		if bs.front_data.get('ymsg_alias') or not is_contact[0]: return
		contact = is_contact[1]
		
		if contact.status.is_offlineish() and not old_substatus.is_offlineish():
			service = YMSGService.LogOff
		elif old_substatus.is_offlineish() and not contact.status.is_offlineish():
			service = YMSGService.LogOn
		elif contact.status.substatus is Substatus.Online:
			service = YMSGService.IsBack
		else:
			service = YMSGService.IsAway
		
		if not (contact.status.is_offlineish() and old_substatus.is_offlineish()):
			yahoo_data = MultiDict()
			if service is not YMSGService.LogOff:
				yahoo_data.add('0', self.ctrl.yahoo_id)
			
			add_contact_status_to_data(yahoo_data, contact.status, contact.head)
			
			self.ctrl.send_reply(service, YMSGStatus.BRB, self.sess_id, yahoo_data)
	
	def on_contact_request_denied(self, user: User, message: str) -> None:
		self.ctrl.send_reply(YMSGService.ContactNew, YMSGStatus.OnVacation, self.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('3', misc.yahoo_id(user.email)),
			('14', message),
		]))
	
	def ymsg_on_p2p_msg_request(self, user_from: User, yahoo_data: Dict[str, Any]) -> None:
		for y in misc.build_p2p_msg_packet(user_from, self.bs, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_xfer_init(self, sender: User, yahoo_data: Dict[str, Any]) -> None:
		for y in misc.build_ft_packet(sender, self.bs, yahoo_data):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		self.ctrl.send_reply(YMSGService.FileTransfer, YMSGStatus.BRB, self.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('5', recipient),
			('4', misc.yahoo_id(self.bs.user.email)),
			('14', message),
		]))
	
	def ymsg_on_sent_ft_http(self, sender: str, url_path: str, upload_time: int, message: str) -> None:
		for y in misc.build_http_ft_packet(self.bs, sender, url_path, upload_time, message):
			self.ctrl.send_reply(y[0], y[1], self.sess_id, y[2])
	
	def ymsg_on_notify_alias_activate(self, activated_alias: str) -> None:
		self.ctrl._update_buddy_list()
		
		self.ctrl._activate_alias(activated_alias)
	
	def ymsg_on_notify_alias_delete(self, deactivated_alias: str) -> None:
		self.ctrl._update_buddy_list()
		
		self.ctrl._deactivate_alias(deactivated_alias)
	
	def on_chat_invite(self, chat: 'Chat', inviter: User, *, invite_msg: str = '') -> None:
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
		for y in misc.build_conf_invite(inviter, self.bs, chat, invite_msg):
			self.ctrl.send_reply(y[0], y[1], self.ctrl.sess_id, y[2])
	
	def on_added_me(self, user: User, *, message: Optional[TextWithData] = None) -> None:
		contact_request_data = MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('3', misc.yahoo_id(user.email)),
		])
		
		if message is not None:
			contact_request_data.add('14', message.text)
			contact_request_data.add('97', message.yahoo_utf8)
		
		contact_request_data.add('15', time.time())
		
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
	
	def on_close(self, keep_future: bool) -> None:
		if not keep_future: self.ctrl.chat_sessions.pop(self.cs.chat, None)
	
	def on_participant_joined(self, cs_other: ChatSession) -> None:
		if self.cs.chat.front_data.get('ymsg_twoway_only'):
			return
		self.ctrl.send_reply(YMSGService.ConfLogon, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('57', cs_other.chat.ids['ymsg/conf']),
			('53', misc.yahoo_id(cs_other.user.email)),
		]))
	
	def on_participant_left(self, cs_other: ChatSession) -> None:
		if 'ymsg/conf' not in cs_other.chat.ids:
			# Yahoo only receives this event in "conferences"
			return
		self.ctrl.send_reply(YMSGService.ConfLogoff, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('57', cs_other.chat.ids['ymsg/conf']),
			('56', misc.yahoo_id(cs_other.user.email)),
		]))
	
	def on_invite_declined(self, invited_user: User, *, message: str = '') -> None:
		self.ctrl.send_reply(YMSGService.ConfDecline, YMSGStatus.BRB, self.ctrl.sess_id, MultiDict([
			('1', misc.yahoo_id(self.bs.user.email)),
			('57', self.cs.chat.ids['ymsg/conf']),
			('54', misc.yahoo_id(invited_user.email)),
			('14', message),
		]))
	
	def on_message(self, data: MessageData) -> None:
		sender = data.sender
		yahoo_data = messagedata_to_ymsg(data)
		
		if data.type is MessageType.Chat:
			if self.cs.chat.front_data.get('ymsg_twoway_only'):
				message_to_dict = MultiDict([
					('5', misc.yahoo_id(self.bs.user.email)),
					('4', misc.yahoo_id(sender.email)),
					('14', yahoo_data.get('14')),
				])
				
				if yahoo_data.get('63') is not None:
					message_to_dict.add('63', yahoo_data.get('63'))
				
				if yahoo_data.get('64') is not None:
					message_to_dict.add('64', yahoo_data.get('64'))
				
				if yahoo_data.get('97') is not None:
					message_to_dict.add('97', yahoo_data.get('97'))
				
				self.ctrl.send_reply(YMSGService.Message, YMSGStatus.BRB, self.ctrl.sess_id, message_to_dict)
			else:
				conf_message_dict = MultiDict([
					('1', misc.yahoo_id(self.bs.user.email)),
					('57', self.cs.chat.ids['ymsg/conf']),
					('3', misc.yahoo_id(sender.email)),
					('14', yahoo_data.get('14')),
				])
				
				if yahoo_data.get('97') is not None:
					conf_message_dict.add('97', yahoo_data.get('97'))
				
				self.ctrl.send_reply(YMSGService.ConfMsg, YMSGStatus.BRB, self.ctrl.sess_id, conf_message_dict)
		elif data.type is MessageType.Typing:
			for y in misc.build_notify_notif(sender, self.bs, yahoo_data):
				self.ctrl.send_reply(y[0], y[1], self.ctrl.sess_id, y[2])
	
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

def messagedata_from_ymsg(sender: User, data: Dict[str, Any], *, notify_type: Optional[str] = None) -> MessageData:
	text = data.get('14') or ''
	
	if notify_type is None:
		type = MessageType.Chat
	elif notify_type == 'TYPING':
		type = MessageType.Typing
	else:
		# TODO: other `notify_type`s
		raise Exception("Unknown notify_type", notify_type)
	
	message = MessageData(sender = sender, type = type, text = text)
	message.front_cache['ymsg'] = data
	return message

def messagedata_to_ymsg(data: MessageData) -> Dict[str, Any]:
	if 'ymsg' not in data.front_cache:
		data.front_cache['ymsg'] = MultiDict([
			('14', data.text),
			('63', ';0'),
			('64', 0),
			('97', 1),
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
	})

def generate_challenge_v1() -> str:
	from uuid import uuid4
	
	# Yahoo64-encode the raw 16 bytes of a UUID
	return Y64.Y64Encode(uuid4().bytes)
