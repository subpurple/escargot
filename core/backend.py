from typing import Dict, List, Set, Any, Tuple, Optional, Callable, Sequence, FrozenSet, Iterable
from abc import ABCMeta, abstractmethod
import asyncio, time, traceback
from collections import defaultdict
from enum import IntFlag

from util.misc import gen_uuid, last_in_iterable, EMPTY_SET, run_loop, Runner, server_temp_cleanup

from .user import UserService
from .auth import AuthService
from .stats import Stats
from .client import Client
from .models import User, UserDetail, Group, Lst, OIM, Contact, ContactDetail, GroupChat, GroupChatRole, GroupChatState, GroupChatMembership, UserStatus, TextWithData, MessageData, Substatus, LoginOption
from . import error, event

class Ack(IntFlag):
	Zero = 0
	NAK = 1
	ACK = 2
	Full = 3

class Backend:
	__slots__ = (
		'user_service', 'auth_service', 'loop', 'notify_maintenance', 'maintenance_mode', 'maintenance_mins',  '_stats', '_sc',
		'_chats_by_id', '_cses_by_bs_by_groupchat_id', '_user_by_uuid', '_worklist_sync_db', '_worklist_sync_groupchats', '_worklist_notify', '_worklist_notify_self', '_runners', '_dev',
	)
	
	user_service: UserService
	auth_service: AuthService
	loop: asyncio.AbstractEventLoop
	notify_maintenance: bool
	maintenance_mode: bool
	maintenance_mins: int
	_stats: Stats
	_sc: '_SessionCollection'
	_chats_by_id: Dict[Tuple[str, str], 'Chat']
	_cses_by_bs_by_groupchat_id: Dict[str, Dict['BackendSession', 'ChatSession']]
	_user_by_uuid: Dict[str, User]
	_worklist_sync_db: Dict[User, UserDetail]
	_worklist_sync_groupchats: Dict[str, GroupChat]
	_worklist_notify: Dict[str, Tuple['BackendSession', Optional[int], bool, Optional[Dict[str, Any]], bool, bool, bool]]
	_worklist_notify_self: Dict[str, 'BackendSession']
	_runners: List[Runner]
	_dev: Optional[Any]
	
	def __init__(self, loop: asyncio.AbstractEventLoop, *, user_service: Optional[UserService] = None, auth_service: Optional[AuthService] = None) -> None:
		self.user_service = user_service or UserService()
		self.auth_service = auth_service or AuthService()
		self.loop = loop
		self.notify_maintenance = False
		self.maintenance_mode = False
		self.maintenance_mins = 0
		self._stats = Stats()
		self._sc = _SessionCollection()
		self._chats_by_id = {}
		self._cses_by_bs_by_groupchat_id = {}
		self._user_by_uuid = {}
		self._worklist_sync_db = {}
		self._worklist_sync_groupchats = {}
		self._worklist_notify = {}
		self._worklist_notify_self = {}
		self._runners = []
		self._dev = None
		
		for groupchat in self.user_service.get_all_groupchats():
			self.chat_create(groupchat = groupchat)
		
		loop.create_task(self._worker_sync_db())
		loop.create_task(self._worker_sync_groupchats())
		loop.create_task(self._worker_clean_sessions())
		loop.create_task(self._worker_sync_stats())
		loop.create_task(self._worker_notify())
		loop.create_task(self._worker_notify_self())
	
	def push_system_message(self, *args: Any, message: str = '', **kwargs: Any) -> None:
		for bs in self._sc.iter_sessions():
			bs.evt.on_system_message(*args, message = message, **kwargs)
		
		if isinstance(args[1], int) and args[1] > 0:
			self.notify_maintenance = True
			self.maintenance_mins = args[1]
			self.loop.create_task(self._worker_set_server_maintenance())
	
	async def _worker_set_server_maintenance(self) -> None:
		while self.maintenance_mins > 0:
			await asyncio.sleep(60)
			self.maintenance_mins -= 1
		
		if self.maintenance_mins <= 0:
			self.notify_maintenance = False
			self.maintenance_mode = True
			for bs in self._sc._sessions.copy():
				bs.evt.on_maintenance_boot()
			server_temp_cleanup()
	
	def add_runner(self, runner: Runner) -> None:
		self._runners.append(runner)
	
	def run_forever(self) -> None:
		run_loop(self.loop, self._runners)
	
	def on_leave(self, sess: 'BackendSession', *, sess_id: Optional[int] = None) -> None:
		user = sess.user
		old_substatus = user.status.substatus
		self._stats.on_logout()
		self._sc.remove_session(sess)
		if not self._sc.get_sessions_by_user(user):
			# User is offline, send notifications
			user.status.substatus = Substatus.Offline
			self._sync_contact_statuses(user)
			self._notify_contacts(sess, for_logout = True)
		for cs_dict in self._cses_by_bs_by_groupchat_id.values():
			cs = cs_dict.get(sess)
			if cs is not None:
				cs.close()
		if self._sc.get_sessions_by_user(user):
			# There are still other people logged in as this user,
			# so don't send offline notifications.
			self._notify_contacts(sess, for_logout = False)
			self._notify_self(sess)
			return
	
	def login(self, uuid: str, client: Client, evt: event.BackendEventHandler, *, option: Optional[LoginOption] = None, only_once: bool = False) -> Optional['BackendSession']:
		user = self._load_user_record(uuid)
		if user is None: return None
		bs_others = self._sc.get_sessions_by_user(user)
		if only_once and bs_others:
			return None
		self.user_service.update_date_login(uuid)
		
		for bs_other in bs_others:
			try:
				if option:
					bs_other.evt.on_login_elsewhere(option)
				else:
					return None
			except:
				traceback.print_exc()
		
		bs = BackendSession(self, user, client, evt)
		bs.evt.bs = bs
		self._stats.on_login()
		self._stats.on_user_active(user, client)
		self._sc.add_session(bs)
		user.detail = self._load_detail(user)
		bs.evt.on_open()
		return bs
	
	def _load_user_record(self, uuid: str) -> Optional[User]:
		if uuid not in self._user_by_uuid:
			user = self.user_service.get(uuid)
			if user is None: return None
			self._user_by_uuid[uuid] = user
		return self._user_by_uuid[uuid]
	
	def _load_detail(self, user: User) -> UserDetail:
		if user.detail: return user.detail
		detail = self.user_service.get_detail(user.uuid)
		assert detail is not None
		return detail
	
	def chat_create(self, *, groupchat: Optional[GroupChat] = None) -> 'Chat':
		return Chat(self, self._stats, groupchat = groupchat)
	
	def chat_get(self, scope: str, id: str) -> Optional['Chat']:
		return self._chats_by_id.get((scope, id))
	
	def get_chats_by_scope(self, scope: str) -> Iterable['Chat']:
		return [chat for (scope_other, _), chat in self._chats_by_id.items() if scope_other is scope]
	
	def join_groupchat(self, chat_id: str, origin: str, bs: 'BackendSession', evt: event.ChatEventHandler, *, pop_id: Optional[str] = None) -> Optional['ChatSession']:
		chat = self.chat_get('persistent', chat_id)
		
		if chat is None: return None
		
		cs = chat.join(origin, bs, evt, pop_id = pop_id)
		if chat_id not in self._cses_by_bs_by_groupchat_id:
			self._cses_by_bs_by_groupchat_id[chat_id] = {}
		self._cses_by_bs_by_groupchat_id[chat_id][bs] = cs
		
		return cs
	
	def get_groupchat_cs(self, chat_id: str, bs: 'BackendSession') -> Optional['ChatSession']:
		if chat_id not in self._cses_by_bs_by_groupchat_id: return None
		
		return self._cses_by_bs_by_groupchat_id[chat_id].get(bs)
	
	def _sync_contact_statuses(self, user: User) -> None:
		detail = user.detail
		if detail is None: return
		for ctc in detail.contacts.values():
			if ctc.lists & Lst.FL:
				ctc.status.old_substatus = ctc.status.substatus
				ctc.status.old_message = ctc.status.message
				ctc.compute_visible_status(user)
			
			# If the contact lists ever become inconsistent (FL without matching RL),
			# the contact that's missing the RL will always see the other user as offline.
			# Because of this, and the fact that most contacts *are* two-way, and it
			# not being that much extra work, I'm leaving this line commented out.
			#if not ctc.lists & Lst.RL: continue
			
			if ctc.head.detail is None: continue
			ctc_rev = ctc.head.detail.contacts.get(user.uuid)
			if ctc_rev is None: continue
			ctc_rev.status.old_substatus = ctc_rev.status.substatus
			ctc_rev.status.old_message = ctc_rev.status.message
			ctc_rev.compute_visible_status(ctc.head)
	
	def _notify_contacts(self, bs: 'BackendSession', *, for_logout: bool = False, sess_id: Optional[int] = None, on_contact_add: bool = False, updated_phone_info: Optional[Dict[str, Any]] = None, update_status: bool = True, send_notif_to_self: bool = True) -> None:
		uuid = bs.user.uuid
		if uuid in self._worklist_notify:
			return
		self._worklist_notify[uuid] = (bs, sess_id, on_contact_add, updated_phone_info, update_status, send_notif_to_self, for_logout)
	
	def _notify_self(self, bs: 'BackendSession') -> None:
		uuid = bs.user.uuid
		if uuid in self._worklist_notify_self:
			return
		self._worklist_notify_self[uuid] = bs
	
	def _mark_modified(self, user: User, *, detail: Optional[UserDetail] = None) -> None:
		ud = user.detail or detail
		if detail: assert ud is detail
		assert ud is not None
		self._worklist_sync_db[user] = ud
	
	def _mark_groupchat_modified(self, groupchat: GroupChat) -> None:
		self._worklist_sync_groupchats[groupchat.chat_id] = groupchat
	
	def util_get_uuid_from_email(self, email: str) -> Optional[str]:
		return self.user_service.get_uuid(email)
	
	def util_set_sess_token(self, sess: 'BackendSession', token: str) -> None:
		self._sc.set_nc_by_token(sess, token)
	
	def util_get_sess_by_token(self, token: str) -> Optional['BackendSession']:
		return self._sc.get_nc_by_token(token)
	
	def util_get_sessions_by_user(self, user: User) -> List['BackendSession']:
		return self._sc.get_sessions_by_user(user)
	
	def dev_connect(self, obj: object) -> None:
		if self._dev is None: return
		self._dev.connect(obj)
	
	def dev_disconnect(self, obj: object) -> None:
		if self._dev is None: return
		self._dev.disconnect(obj)
	
	async def _worker_sync_db(self) -> None:
		while True:
			await asyncio.sleep(1)
			self._sync_db_impl()
	
	def _sync_db_impl(self) -> None:
		if not self._worklist_sync_db: return
		try:
			users = list(self._worklist_sync_db.keys())[:100]
			batch = []
			for user in users:
				detail = self._worklist_sync_db.pop(user, None)
				if detail is None: continue
				batch.append((user, detail))
			self.user_service.save_batch(batch)
		except:
			traceback.print_exc()
	
	async def _worker_sync_groupchats(self) -> None:
		while True:
			await asyncio.sleep(1)
			self._sync_groupchat_impl()
	
	def _sync_groupchat_impl(self) -> None:
		if not self._worklist_sync_groupchats: return
		try:
			chat_ids = list(self._worklist_sync_groupchats.keys())[:100]
			batch = []
			for chat_id in chat_ids:
				groupchat = self._worklist_sync_groupchats.pop(chat_id, None)
				if groupchat is None: continue
				batch.append((chat_id, groupchat))
			self.user_service.save_groupchat_batch(batch)
		except:
			traceback.print_exc()
	
	async def _worker_clean_sessions(self) -> None:
		while True:
			await asyncio.sleep(10)
			now = time.time()
			closed = []
			
			try:
				for sess in self._sc.iter_sessions():
					if sess.closed:
						closed.append(sess)
			except:
				traceback.print_exc()
			
			for sess in closed:
				self._sc.remove_session(sess)
	
	async def _worker_sync_stats(self) -> None:
		while True:
			await asyncio.sleep(60)
			try:
				self._stats.flush()
			except:
				traceback.print_exc()
	
	async def _worker_notify(self) -> None:
		# Notify relevant `BackendSession`s of status, name, message, media, etc. changes
		worklist = self._worklist_notify
		while True:
			await asyncio.sleep(0.2)
			try:
				for bs, sess_id, on_contact_add, updated_phone_info, update_status, send_notif_to_self, for_logout in worklist.values():
					user = bs.user
					detail = user.detail
					assert detail is not None
					for ctc in detail.contacts.values():
						for bs_other in self._sc.get_sessions_by_user(ctc.head):
							if bs_other.user is user and not send_notif_to_self: continue
							detail_other = bs_other.user.detail
							if detail_other is None: continue
							ctc_me = detail_other.contacts.get(user.uuid)
							# This shouldn't be `None`, since every contact should have
							# an `RL` contact on the other users' list (at the very least).
							if ctc_me is None: continue
							if not ctc_me.lists & Lst.FL: continue
							bs_other.evt.on_presence_notification(bs, ctc_me, on_contact_add, sess_id = sess_id, update_status = update_status, updated_phone_info = updated_phone_info)
					for groupchat in self.user_service.get_groupchat_batch(user):
						if groupchat.chat_id not in self._cses_by_bs_by_groupchat_id: continue
						if bs not in self._cses_by_bs_by_groupchat_id[groupchat.chat_id]: continue
						cs = self._cses_by_bs_by_groupchat_id[groupchat.chat_id][bs]
						cs.chat.send_participant_presence(cs)
					if for_logout:
						if not self._sc.get_sessions_by_user(user): user.detail = None
			except:
				traceback.print_exc()
			worklist.clear()
	
	async def _worker_notify_self(self) -> None:
		# Notify relevant `BackendSession`s of status, name, message, media, etc. changes
		worklist = self._worklist_notify_self
		while True:
			await asyncio.sleep(0.2)
			try:
				for bs in worklist.values():
					user = bs.user
					for bs_other in self._sc.get_sessions_by_user(user):
						bs_other.evt.on_presence_self_notification()
			except:
				traceback.print_exc()
			worklist.clear()

class Session(metaclass = ABCMeta):
	__slots__ = ('closed',)
	
	closed: bool
	
	def __init__(self) -> None:
		self.closed = False
	
	def close(self, **kwargs: Any) -> None:
		if self.closed:
			return
		self.closed = True
		self._on_close(**kwargs)
	
	@abstractmethod
	def _on_close(self, **kwargs: Any) -> None: pass

class BackendSession(Session):
	__slots__ = ('backend', 'user', 'client', 'evt', 'front_data')
	
	backend: Backend
	user: User
	client: Client
	evt: event.BackendEventHandler
	front_data: Dict[str, Any]
	
	def __init__(self, backend: Backend, user: User, client: Client, evt: event.BackendEventHandler) -> None:
		super().__init__()
		self.backend = backend
		self.user = user
		self.client = client
		self.evt = evt
		self.front_data = {}
	
	def _on_close(self, **kwargs: Any) -> None:
		if not kwargs.get('passthrough'): self.evt.on_close()
		self.backend.on_leave(self, sess_id = kwargs.get('sess_id'))
	
	def me_update(self, fields: Dict[str, Any]) -> None:
		user = self.user
		
		needs_notify = False
		notify_status = False
		notify_self = False
		send_notif_to_self = False
		updated_phone_info = {}
		notify_circle = False
		
		old_substatus = user.status.substatus
		
		if 'needs_notify' in fields:
			needs_notify = fields['needs_notify']
		if 'message' in fields:
			if fields['message'] is not None:
				old_message = user.status.message
				user.status.set_status_message(fields['message'], persistent = not fields.get('message_temp'))
				needs_notify = True
				notify_status = True
				if 'send_notif_to_self' in fields and fields['message'] != old_message:
					send_notif_to_self = fields['send_notif_to_self']
		if 'media' in fields:
			if fields['media'] is not None:
				user.status.media = fields['media']
				needs_notify = True
				notify_status = True
		if 'name' in fields:
			user.status.name = fields['name']
			needs_notify = True
			notify_status = True
		if 'home_phone' in fields:
			if fields['home_phone'] is None and 'PHH' in user.settings:
				del user.settings['PHH']
			else:
				user.settings['PHH'] = fields['home_phone']
			needs_notify = True
			updated_phone_info['PHH'] = fields['home_phone']
		if 'work_phone' in fields:
			if fields['work_phone'] is None and 'PHW' in user.settings:
				del user.settings['PHW']
			else:
				user.settings['PHW'] = fields['work_phone']
			needs_notify = True
			updated_phone_info['PHW'] = fields['work_phone']
		if 'mobile_phone' in fields:
			if fields['mobile_phone'] is None and 'PHM' in user.settings:
				del user.settings['PHM']
			else:
				user.settings['PHM'] = fields['mobile_phone']
			needs_notify = True
			updated_phone_info['PHM'] = fields['mobile_phone']
		if 'blp' in fields:
			user.settings['BLP'] = fields['blp']
			needs_notify = True
			notify_status = True
		if 'mob' in fields:
			user.settings['MOB'] = fields['mob']
			needs_notify = True
			updated_phone_info['MOB'] = fields['mob']
		if 'mbe' in fields:
			user.settings['MBE'] = fields['mbe']
			needs_notify = True
			updated_phone_info['MBE'] = fields['mbe']
		if 'substatus' in fields:
			if fields['substatus'] is not None:
				user.status.substatus = fields['substatus']
				if old_substatus is not user.status.substatus or fields.get('refresh_profile'):
					needs_notify = True
					notify_status = True
					if 'send_notif_to_self' in fields:
						send_notif_to_self = fields['send_notif_to_self']
		if 'notify_self' in fields:
			notify_self = fields['notify_self']
		if 'gtc' in fields:
			user.settings['GTC'] = fields['gtc']
		if 'rlp' in fields:
			user.settings['RLP'] = fields['rlp']
		if 'mpop' in fields:
			user.settings['MPOP'] = fields['mpop']
		
		self.backend._mark_modified(user)
		if needs_notify:
			self.backend._sync_contact_statuses(user)
			self.backend._notify_contacts(self, updated_phone_info = updated_phone_info, update_status = notify_status, send_notif_to_self = send_notif_to_self)
		if notify_self:
			self.backend._notify_self(self)
	
	def me_group_add(self, name: str) -> Group:
		if len(name) > MAX_GROUP_NAME_LENGTH:
			raise error.GroupNameTooLong()
		user = self.user
		detail = user.detail
		assert detail is not None
		if name == '(No Group)':
			raise error.GroupAlreadyExists()
		groups = detail.get_groups_by_name(name)
		if groups is not None:
			name += str(len(groups))
		group = Group(_gen_group_id(detail), gen_uuid(), name, False)
		detail.insert_group(group)
		self.backend._mark_modified(user)
		return group
	
	def me_group_remove(self, group_id: str) -> None:
		if group_id == '0':
			raise error.CannotRemoveSpecialGroup()
		user = self.user
		detail = user.detail
		assert detail is not None
		group = detail.get_group_by_id(group_id)
		if group is None:
			raise error.GroupDoesNotExist()
		detail.delete_group(group)
		for ctc in detail.contacts.values():
			ctc.remove_from_group(group)
		self.backend._mark_modified(user)
	
	def me_group_edit(self, group_id: str, *, new_name: Optional[str] = None, is_favorite: Optional[bool] = None) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		g = detail.get_group_by_id(group_id)
		if g is None:
			raise error.GroupDoesNotExist()
		if new_name is not None:
			if new_name == '(No Group)':
				raise error.GroupAlreadyExists()
			if len(new_name) > MAX_GROUP_NAME_LENGTH:
				raise error.GroupNameTooLong()
			g.name = new_name
		if is_favorite is not None:
			g.is_favorite = is_favorite
		self.backend._mark_modified(user)
	
	def me_group_contact_add(self, group_id: str, contact_uuid: str) -> None:
		if group_id == '0': return
		user = self.user
		detail = user.detail
		assert detail is not None
		group = detail.get_group_by_id(group_id)
		if group is None:
			raise error.GroupDoesNotExist()
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if ctc.group_in_entry(group):
			raise error.ContactAlreadyOnList()
		ctc.add_group_to_entry(group)
		self.backend._mark_modified(user)
	
	def me_group_contact_remove(self, group_id: str, contact_uuid: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id != '0':
			group = detail.get_group_by_id(group_id)
			if group is None:
				raise error.GroupDoesNotExist()
			ctc.remove_from_group(group)
			self.backend._mark_modified(user)
	
	def me_contact_add(self, contact_uuid: str, lst: Lst, *, trid: Optional[str] = None, name: Optional[str] = None, nickname: Optional[str] = None, message: Optional[TextWithData] = None, group_id: Optional[str] = None, adder_id: Optional[str] = None, needs_notify: bool = False) -> Tuple[Contact, User]:
		assert not lst & Lst.PL
		backend = self.backend
		ctc_head = backend._load_user_record(contact_uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		user = self.user
		ctc_status = ctc_head.status.substatus
		ctc = self._add_to_list(user, ctc_head, lst, name, group_id, nickname = nickname)
		if lst & Lst.FL:
			# FL needs a matching RL on the contact
			ctc_me = self._add_to_list(ctc_head, user, Lst.RL, user.email, None) # type: Optional[Contact]
			# `ctc_head` was added to `user`'s RL
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				#if sess_added is self: continue
				sess_added.evt.on_added_me(user, message = message, adder_id = adder_id)
		else:
			ctc_detail = backend._load_detail(ctc_head)
			ctc_me = ctc_detail.contacts.get(user.uuid)
		if ((lst & Lst.AL or lst & Lst.BL) and ctc.lists & Lst.RL) or needs_notify:
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				if sess_added is self: continue
				if ctc_me:
					if ctc_me.lists & Lst.FL:
						sess_added.evt.on_presence_notification(self, ctc_me, False, visible_notif = False, send_status_on_bl = True, updated_phone_info = {
							'PHH': user.settings.get('PHH'),
							'PHW': user.settings.get('PHW'),
							'PHM': user.settings.get('PHM'),
							'MOB': user.settings.get('MOB'),
						})
		return ctc, ctc_head
	
	def me_contact_rename(self, contact_uuid: str, new_name: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		
		if len(new_name) > 387:
			raise error.NicknameExceedsLengthLimit()
		
		ctc.status.name = new_name
		self.backend._mark_modified(user)
	
	def me_contact_remove(self, contact_uuid: str, lst: Lst, *, group_id: Optional[str] = None) -> None:
		backend = self.backend
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None: 
			raise error.ContactDoesNotExist()
		assert not lst & Lst.RL
		self._remove_from_list(user, ctc.head, lst, group_id)
		if lst & Lst.FL:
			# Remove matching RL
			self._remove_from_list(ctc.head, user, Lst.RL, None)
		if lst & Lst.BL:
			ctc_detail = backend._load_detail(ctc.head)
			ctc_me = ctc_detail.contacts.get(user.uuid)
			for sess_added in backend._sc.get_sessions_by_user(ctc.head):
				if sess_added is self: continue
				if ctc_me:
					if ctc_me.lists & Lst.FL:
						sess_added.evt.on_presence_notification(self, ctc_me, False, updated_phone_info = {
							'PHH': user.settings.get('PHH'),
							'PHW': user.settings.get('PHW'),
							'PHM': user.settings.get('PHM'),
							'MOB': user.settings.get('MOB'),
						})
	
	def me_contact_deny(self, adder_uuid: str, deny_message: Optional[str], *, addee_id: Optional[str] = None) -> None:
		user_adder = self.backend._load_user_record(adder_uuid)
		if user_adder is None:
			raise error.UserDoesNotExist()
		user = self.user
		for sess_adder in self.backend._sc.get_sessions_by_user(user_adder):
			sess_adder.evt.on_contact_request_denied(user, deny_message or '', contact_id = addee_id)
	
	def _add_to_list(self, user: User, ctc_head: User, lst: Lst, name: Optional[str], group_id: Optional[str], *, nickname: Optional[str] = None) -> Contact:
		# Add `ctc` to `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		
		updated = False
		
		if ctc_head.uuid not in contacts:
			contacts[ctc_head.uuid] = Contact(ctc_head, set(), Lst.Empty, UserStatus(name), ContactDetail(_gen_contact_id(detail)))
			updated = True
		ctc = contacts[ctc_head.uuid]
		
		if (ctc.lists & lst) != lst:
			ctc.lists |= lst
			updated = True
		else:
			if lst == Lst.FL and group_id is not None:
				if ctc.is_in_group_id(group_id):
					raise error.ContactAlreadyOnList()
		
		orig_name = ctc.status.name
		if name is not None and (ctc.status.name is None or orig_name != name):
			ctc.status.name = name
			updated = True
		
		orig_nick = ctc.detail.nickname
		if nickname is not None and (ctc.detail.nickname is None or orig_nick != nickname):
			ctc.detail.nickname = nickname
			updated = True
		
		if lst == Lst.FL:
			if group_id is not None:
				try:
					self.me_group_contact_add(group_id, ctc_head.uuid)
				except Exception as ex:
					raise ex
		
		if updated:
			self.backend._mark_modified(user, detail = detail)
			self.backend._sync_contact_statuses(user)
		
		return ctc
	
	def _remove_from_list(self, user: User, ctc_head: User, lst: Lst, group_id: Optional[str]) -> None:
		# Remove `ctc_head` from `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		ctc = contacts.get(ctc_head.uuid)
		if ctc is None: return
		
		updated = False
		if ctc.lists & lst:
			if lst == Lst.FL and group_id is not None:
				try:
					self.me_group_contact_remove(group_id, ctc.head.uuid)
				except Exception as ex:
					raise ex
				updated = True
				
			if (lst == Lst.FL and group_id is None) or not lst & Lst.FL:
				ctc.lists &= ~lst
				if lst == Lst.FL:
					ctc._groups = set()
				updated = True
		
		if not ctc.lists:
			del contacts[ctc_head.uuid]
			updated = True
		
		if updated:
			self.backend._mark_modified(user, detail = detail)
			self.backend._sync_contact_statuses(user)
	
	def me_contact_notify_oim(self, uuid: str, oim: OIM) -> None:
		ctc_head = self.backend._load_user_record(uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		
		for sess_notify in self.backend._sc.get_sessions_by_user(ctc_head):
			if sess_notify is self: continue
			sess_notify.evt.on_oim_sent(oim)
	
	def me_create_groupchat(self, name: str, owner_friendly: str, membership_access: int) -> str:
		user = self.user
		backend = self.backend
		
		chat_id = backend.user_service.create_groupchat(user, name, owner_friendly, membership_access)
		groupchat = backend.user_service.get_groupchat(chat_id)
		assert groupchat is not None
		
		backend.chat_create(groupchat = groupchat)
		
		return chat_id
	
	def me_add_user_to_groupchat(self, groupchat: GroupChat, user_other: User) -> None:
		user = self.user
		
		if user_other.uuid in groupchat.memberships: raise error.MemberAlreadyInGroupChat()
		groupchat.memberships[user_other.uuid] = GroupChatMembership(
			groupchat.chat_id, user_other,
			GroupChatRole.Empty, GroupChatState.Empty,
		)
		
		self.backend._mark_groupchat_modified(groupchat)
	
	def me_invite_user_to_groupchat(self, groupchat: GroupChat, invitee: User, *, invite_message: Optional[str] = None) -> None:
		backend = self.backend
		inviter = self.user
		
		if invitee.uuid not in groupchat.memberships: raise error.MemberNotInGroupChat()
		
		membership = groupchat.memberships[invitee.uuid]
		
		if not (membership.role == GroupChatRole.Empty or membership.state == GroupChatState.Empty): raise error.MemberAlreadyInvitedToGroupChat()
		
		chat = backend.chat_get('persistent', groupchat.chat_id)
		if chat is None: raise error.GroupChatDoesNotExist()
		
		membership.role = GroupChatRole.StatePendingOutbound
		membership.state = GroupChatState.WaitingResponse
		membership.inviter_uuid = inviter.uuid
		membership.inviter_email = inviter.email
		membership.inviter_name = inviter.status.name or inviter.email
		membership.invite_message = invite_message
		
		self.backend._mark_groupchat_modified(groupchat)
		
		for bs in backend.util_get_sessions_by_user(invitee):
			bs.evt.on_chat_invite(chat, inviter, group_chat = True)
	
	def me_change_groupchat_membership(self, groupchat: GroupChat, user_other: User, *, role: Optional[GroupChatRole] = None, state: Optional[GroupChatState] = None, bs: Optional['BackendSession'] = None) -> None:
		user = self.user
		
		if user_other.uuid not in groupchat.memberships: raise error.MemberNotInGroupChat()
		
		chat = self.backend.chat_get('persistent', groupchat.chat_id)
		if chat is None: raise error.GroupChatDoesNotExist()
		
		membership = groupchat.memberships[user_other.uuid]
		
		old_role = membership.role
		old_state = membership.state
		if role is not None:
			membership.role = role
		if state is not None:
			membership.state = state
		
		if old_role is not membership.role or old_state is not membership.state:
			self.backend._mark_groupchat_modified(groupchat)
			for cs_other in chat.get_roster():
				for bs_other in self.backend.util_get_sessions_by_user(cs_other.user):
					if bs is not None and bs_other is bs: continue
					bs_other.evt.on_groupchat_role_updated(groupchat.chat_id, role = membership.role)
	
	def me_send_uun_invitation(self, uuid: str, type: int, data: Optional[bytes], *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
		ctc_head = self.backend._load_user_record(uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		
		for sess_notify in self.backend._sc.get_sessions_by_user(ctc_head):
			#if sess_notify is self: continue
			sess_notify.evt.msn_on_uun_sent(self.user, type, data, pop_id_sender = pop_id_sender, pop_id = pop_id)

class _SessionCollection:
	__slots__ = ('_sessions', '_sessions_by_user', '_sess_by_token', '_tokens_by_sess')
	
	_sessions: Set[BackendSession]
	_sessions_by_user: Dict[User, List[BackendSession]]
	_sess_by_token: Dict[str, BackendSession]
	_tokens_by_sess: Dict[BackendSession, Set[str]]
	
	def __init__(self) -> None:
		self._sessions = set()
		self._sessions_by_user = defaultdict(list)
		self._sess_by_token = {}
		self._tokens_by_sess = defaultdict(set)
	
	def get_sessions_by_user(self, user: User) -> List[BackendSession]:
		if user not in self._sessions_by_user:
			return []
		return self._sessions_by_user[user]
	
	def iter_sessions(self) -> Iterable[BackendSession]:
		yield from self._sessions
	
	def set_nc_by_token(self, sess: BackendSession, token: str) -> None:
		self._sess_by_token[token] = sess
		self._tokens_by_sess[sess].add(token)
		self._sessions.add(sess)
	
	def get_nc_by_token(self, token: str) -> Optional[BackendSession]:
		return self._sess_by_token.get(token)
	
	def add_session(self, sess: BackendSession) -> None:
		if sess.user:
			self._sessions_by_user[sess.user].append(sess)
		self._sessions.add(sess)
	
	def remove_session(self, sess: BackendSession) -> None:
		if sess in self._tokens_by_sess:
			tokens = self._tokens_by_sess.pop(sess)
			for token in tokens:
				self._sess_by_token.pop(token, None)
		self._sessions.discard(sess)
		if sess.user in self._sessions_by_user:
			self._sessions_by_user[sess.user].remove(sess)

class Chat:
	__slots__ = ('ids', 'backend', 'groupchat', 'front_data', '_users_by_sess', '_stats')
	
	ids: Dict[str, str]
	backend: Backend
	groupchat: Optional[GroupChat]
	front_data: Dict[str, Any]
	_users_by_sess: Dict['ChatSession', Tuple[User, Optional[str]]]
	_stats: Any
	
	def __init__(self, backend: Backend, stats: Any, *, groupchat: Optional[GroupChat] = None) -> None:
		super().__init__()
		self.ids = {}
		self.backend = backend
		self.groupchat = groupchat
		self.front_data = {}
		self._users_by_sess = {}
		self._stats = stats
		
		self.add_id('main', backend.auth_service.GenTokenStr(trim = 10))
		if self.groupchat is None: return
		
		assert groupchat is not None
		self.add_id('persistent', groupchat.chat_id)
	
	def add_id(self, scope: str, id: str) -> None:
		assert id not in self.backend._chats_by_id
		self.ids[scope] = id
		self.backend._chats_by_id[(scope, id)] = self
	
	def join(self, origin: str, bs: BackendSession, evt: event.ChatEventHandler, *, preferred_name: Optional[str] = None, pop_id: Optional[str] = None) -> 'ChatSession':
		primary_pop = True
		
		if self.groupchat is not None:
			if bs.user.uuid not in self.groupchat.memberships: raise error.NotAllowedToJoinGroupChat()
		
		for user_other, pop_id_other in self._users_by_sess.values():
			if bs.user is user_other:
				if pop_id_other is not None:
					if (pop_id is not None and pop_id_other.lower() == pop_id.lower()): raise error.AuthFail()
				else:
					if pop_id is not None: raise error.AuthFail()
		for other_cs in self.get_roster():
			primary_pop = True
			if other_cs.user is bs.user and other_cs.primary_pop:
				primary_pop = False
		cs = ChatSession(origin, bs, self, evt, primary_pop, preferred_name = preferred_name)
		cs.evt.cs = cs
		self._users_by_sess[cs] = (cs.user, pop_id)
		cs.evt.on_open()
		return cs
	
	def add_session(self, cs: 'ChatSession', pop_id: Optional[str] = None) -> None:
		self._users_by_sess[cs] = (cs.user, pop_id)
	
	def get_roster(self) -> Iterable['ChatSession']:
		return self._users_by_sess.keys()
	
	def get_roster_single(self) -> Iterable['ChatSession']:
		sess_per_user = [] # type: List[ChatSession]
		
		for cs in self._users_by_sess.keys():
			already_in_roster = False
			for sess1 in sess_per_user:
				if cs.primary_pop:
					if sess1.user is cs.user:
						already_in_roster = True
					break
			if not already_in_roster:
				sess_per_user.append(cs)
		
		return sess_per_user
	
	def send_participant_joined(self, cs: 'ChatSession') -> None:
		tmp = []
		
		cs.joined = True
		
		for cs_self in self.get_roster():
			if cs_self.user is cs.user and cs_self is not cs:
				tmp.append(cs_self)
		
		if len(tmp) > 0:
			first_pop = False
		else:
			first_pop = True
		
		for cs_other in self.get_roster():
			if cs_other is cs and cs.origin is 'yahoo': continue
			cs_other.evt.on_participant_joined(cs, first_pop)
	
	def send_participant_presence(self, cs: 'ChatSession', *, initial_presence: bool = False) -> None:
		tmp = []
		
		for cs_self in self.get_roster():
			if cs_self.user is cs.user and cs_self is not cs:
				tmp.append(cs_self)
		
		if len(tmp) > 0:
			first_pop = False
		else:
			first_pop = True
		
		if initial_presence:
			for cs_other in self.get_roster():
				if cs_other is cs: continue
				cs.evt.on_participant_presence(cs_other, cs.primary_pop)
		
		for cs_other in self.get_roster():
			if cs_other is cs and cs.origin is 'yahoo': continue
			cs_other.evt.on_participant_presence(cs, first_pop)
	
	def on_leave(self, sess: 'ChatSession', keep_future: bool, idle: bool, send_idle_leave: bool) -> None:
		su = self._users_by_sess.pop(sess, None)
		if su is None: return
		last_pop = False
		# TODO: If it goes down to only 1 connected user,
		# the chat and remaining session(s) should be automatically closed.
		if not self._users_by_sess and not (keep_future or self.groupchat):
			for scope_id in self.ids.items():
				del self.backend._chats_by_id[scope_id]
			return
		sess_others = [sess_other for sess_other in self._users_by_sess.keys() if sess_other.user is su[0]]
		if sess_others:
			no_primary_pop = True
			for sess_other in sess_others:
				if sess_other.primary_pop:
					no_primary_pop = False
					break
			if no_primary_pop:
				sess_others[-1].primary_pop = True
		else:
			last_pop = True
		# Notify others that `sess` has left
		if (idle and send_idle_leave) or not idle:
			for sess1, _ in self._users_by_sess.items():
				if sess1 is sess: continue
				sess1.evt.on_participant_left(sess, idle, last_pop)

class ChatSession(Session):
	__slots__ = ('origin', 'user', 'chat', 'bs', 'evt', 'primary_pop', 'joined', 'front_data', 'preferred_name')
	
	origin: Optional[str]
	user: User
	chat: Chat
	bs: BackendSession
	evt: event.ChatEventHandler
	primary_pop: bool
	joined: bool
	front_data: Dict[str, Any]
	preferred_name: Optional[str]
	
	def __init__(self, origin: str, bs: BackendSession, chat: Chat, evt: event.ChatEventHandler, primary_pop: bool, *, preferred_name: Optional[str] = None) -> None:
		super().__init__()
		self.origin = origin
		self.user = bs.user
		self.chat = chat
		self.bs = bs
		self.evt = evt
		self.primary_pop = primary_pop
		self.joined = False
		self.front_data = {}
		self.preferred_name = preferred_name
	
	def _on_close(self, **kwargs: Any) -> None:
		keep_future = kwargs.pop('keep_future', False)
		idle = kwargs.pop('idle', False)
		send_idle_leave = kwargs.pop('send_idle_leave', False)
		self.evt.on_close(keep_future, idle)
		self.chat.on_leave(self, keep_future, idle, send_idle_leave)
	
	def invite(self, invitee: User, *, invite_msg: Optional[str] = None) -> None:
		already_invited_sessions = [] # type: List[BackendSession]
		
		ctc_sessions = self.bs.backend.util_get_sessions_by_user(invitee)
		roster = list(self.chat.get_roster())
		for cs_other in roster:
			if cs_other.bs in already_invited_sessions: continue
			for ctc_sess in ctc_sessions:
				if cs_other.bs is ctc_sess and self.origin is not 'yahoo':
					already_invited_sessions.append(ctc_sess)
		for ctc_sess in ctc_sessions:
			if ctc_sess in already_invited_sessions: continue
			ctc_sess.evt.on_chat_invite(self.chat, self.user, invite_msg = invite_msg or '')
		
		if len(ctc_sessions) == len(already_invited_sessions): raise error.ContactAlreadyOnList()
	
	def update_status(self) -> None:
		for cs_other in self.chat._users_by_sess.keys():
			cs_other.evt.on_participant_status_updated(self)
	
	def send_message_to_everyone(self, data: MessageData) -> None:
		stats = self.chat._stats
		client = self.bs.client
		
		stats.on_message_sent(self.user, client)
		stats.on_user_active(self.user, client)
		
		for cs_other in self.chat._users_by_sess.keys():
			if cs_other is self: continue
			cs_other.evt.on_message(data)
			stats.on_message_received(cs_other.user, client)
	
	def send_message_to_user(self, user_uuid: str, data: MessageData) -> None:
		stats = self.chat._stats
		client = self.bs.client
		
		stats.on_message_sent(self.user, client)
		stats.on_user_active(self.user, client)
		
		for cs_other in self.chat._users_by_sess.keys():
			if cs_other is self: continue
			if cs_other.user.uuid != user_uuid: continue
			cs_other.evt.on_message(data)
			stats.on_message_received(cs_other.user, client)

def _gen_group_id(detail: UserDetail) -> str:
	id = 1
	s = str(id)
	while s in detail._groups_by_id:
		id += 1
		s = str(id)
	return s

def _gen_contact_id(detail: UserDetail) -> str:
	id = 2
	for i, _ in enumerate(detail.contacts.values()):
		if i+2 == id:
			id += 1
			continue
	s = str(id)
	
	return s

MAX_GROUP_NAME_LENGTH = 61
