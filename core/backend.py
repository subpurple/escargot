from typing import Dict, List, Set, Any, Tuple, Optional, Callable, Sequence, FrozenSet, Iterable
from abc import ABCMeta, abstractmethod
import asyncio, time, traceback
from collections import defaultdict
from enum import IntFlag

from util.misc import gen_uuid, EMPTY_SET, run_loop, Runner, server_temp_cleanup

from .user import UserService
from .auth import AuthService
from .stats import Stats
from .client import Client
from .models import User, UserDetail, Group, ABGroup, Lst, NetworkID, Contact, ABContact, UserStatus, TextWithData, MessageData, Substatus, LoginOption
from . import error, event

class Ack(IntFlag):
	Zero = 0
	NAK = 1
	ACK = 2
	Full = 3

class Backend:
	__slots__ = (
		'user_service', 'auth_service', 'loop', 'notify_maintenance', 'maintenance_mode', 'maintenance_mins',  '_stats', '_sc',
		'_chats_by_id', '_user_by_uuid', '_worklist_sync_db', '_worklist_notify', '_runners', '_dev',
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
	_user_by_uuid: Dict[str, User]
	_worklist_sync_db: Dict[User, UserDetail]
	_worklist_notify: Dict[str, Tuple['BackendSession', Substatus, bool]]
	_runners: List[Runner]
	_dev: Optional[Any]
	
	def __init__(self, loop: asyncio.AbstractEventLoop, *, user_service: Optional[UserService] = None, auth_service: Optional[AuthService] = None) -> None:
		self.user_service = user_service or UserService(loop)
		self.auth_service = auth_service or AuthService()
		self.loop = loop
		self.notify_maintenance = False
		self.maintenance_mode = False
		self.maintenance_mins = 0
		self._stats = Stats()
		self._sc = _SessionCollection()
		self._chats_by_id = {}
		self._user_by_uuid = {}
		self._worklist_sync_db = {}
		self._worklist_notify = {}
		self._runners = []
		self._dev = None
		
		loop.create_task(self._worker_sync_db())
		loop.create_task(self._worker_clean_sessions())
		loop.create_task(self._worker_sync_stats())
		loop.create_task(self._worker_notify())
	
	def push_system_message(self, *args: Any, message: str = '', **kwargs: Any) -> None:
		for bs in self._sc.iter_sessions():
			bs.evt.on_system_message(*args, message = message, **kwargs)
		
		if isinstance(args[1], int) and args[1] > 0:
			self.notify_maintenance = True
			self.maintenance_mins = args[1]
			self.loop.create_task(self._worker_set_server_maintenance())
	
	async def _worker_set_server_maintenance(self):
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
	
	def on_leave(self, sess: 'BackendSession') -> None:
		user = sess.user
		old_substatus = user.status.substatus
		self._stats.on_logout()
		user_sess_list = self._sc.get_sessions_by_user(user)
		if len(user_sess_list) - 1 >= 1:
			# There are still other people logged in as this user,
			# so don't send offline notifications.
			return
		# User is offline, send notifications
		user.status.substatus = Substatus.Offline
		sess.evt.on_sync_contact_statuses()
		self._notify_contacts(sess, for_logout = True, old_substatus = old_substatus)
	
	def login(self, uuid: str, client: Optional[Client], evt: event.BackendEventHandler, *, option: Optional[LoginOption] = None, message_temp: bool = False, only_once: bool = False) -> Optional['BackendSession']:
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
		
		bs = BackendSession(self, user, client, evt, message_temp)
		bs.evt.bs = bs
		if client is not None:
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
	
	def chat_create(self) -> 'Chat':
		return Chat(self, self._stats)
	
	def chat_get(self, scope: str, id: str) -> Optional['Chat']:
		return self._chats_by_id.get((scope, id))
	
	def _notify_contacts(self, bs: 'BackendSession', *, for_logout: bool = False, old_substatus: Substatus = Substatus.Offline, on_contact_add: bool = False, updated_phone_info: Optional[Dict[str, Any]] = None, update_status: bool = True, send_notif_to_self: bool = True) -> None:
		uuid = bs.user.uuid
		if uuid in self._worklist_notify:
			return
		self._worklist_notify[uuid] = (bs, old_substatus, on_contact_add, updated_phone_info, update_status, send_notif_to_self, for_logout)
	
	def _mark_modified(self, user: User, *, message_temp: bool = False, detail: Optional[UserDetail] = None) -> None:
		ud = user.detail or detail
		if detail: assert ud is detail
		assert ud is not None
		self._worklist_sync_db[user] = (ud, message_temp)
	
	def util_get_uuid_from_email(self, email: str, networkid: NetworkID) -> Optional[str]:
		return self.user_service.get_uuid(email, networkid)
	
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
				detail, message_temp = self._worklist_sync_db.pop(user, None)
				if not detail: continue
				batch.append((user, detail, message_temp))
			self.user_service.save_batch(batch)
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
				for bs, old_substatus, on_contact_add, updated_phone_info, update_status, send_notif_to_self, for_logout in worklist.values():
					user = bs.user
					for bs_other in self._sc.iter_sessions():
						if bs_other.user is user and not send_notif_to_self: continue
						bs_other.evt.on_presence_notification(bs.user, old_substatus, on_contact_add, update_status = update_status, updated_phone_info = updated_phone_info)
					if for_logout:
						if not self._sc.get_sessions_by_user(user): user.detail = None
			except:
				traceback.print_exc()
			worklist.clear()

class Session(metaclass = ABCMeta):
	__slots__ = ('closed',)
	
	closed: bool
	
	def __init__(self) -> None:
		self.closed = False
	
	def close(self, **kwargs) -> None:
		if self.closed:
			return
		self.closed = True
		self._on_close(**kwargs)
	
	@abstractmethod
	def _on_close(self) -> None: pass

class BackendSession(Session):
	__slots__ = ('backend', 'user', 'client', 'evt', 'message_temp', 'front_data')
	
	backend: Backend
	user: User
	client: Client
	evt: event.BackendEventHandler
	message_temp: bool
	front_data: Dict[str, Any]
	
	def __init__(self, backend: Backend, user: User, client: Client, evt: event.BackendEventHandler, message_temp: bool) -> None:
		super().__init__()
		self.backend = backend
		self.user = user
		self.client = client
		self.evt = evt
		self.message_temp = message_temp
		self.front_data = {}
	
	def _on_close(self, **kwargs) -> None:
		if not kwargs.get('passthrough'): self.evt.on_close()
		self.backend.on_leave(self)
	
	def me_update(self, fields: Dict[str, Any]) -> None:
		user = self.user
		
		needs_notify = False
		notify_status = False
		send_notif_to_self = True
		updated_phone_info = {}
		notify_circle = False
		
		old_substatus = user.status.substatus
		
		if 'message' in fields:
			if fields['message'] is not None:
				user.status.message = fields['message']
				needs_notify = True
				notify_status = True
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
			user.status.substatus = fields['substatus']
			if old_substatus != user.status.substatus or fields['refresh_profile']:
				needs_notify = True
				notify_status = True
				if 'send_notif_to_self' in fields:
					send_notif_to_self = fields['send_notif_to_self']
		if 'gtc' in fields:
			user.settings['GTC'] = fields['gtc']
		if 'rlp' in fields:
			user.settings['RLP'] = fields['rlp']
		
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if needs_notify:
			self.evt.on_sync_contact_statuses()
			self.backend._notify_contacts(self, old_substatus = old_substatus, updated_phone_info = updated_phone_info, update_status = notify_status, send_notif_to_self = send_notif_to_self)
	
	def me_group_add(self, name: str, *, add_to_ab: bool = False) -> Group:
		if len(name) > MAX_GROUP_NAME_LENGTH:
			raise error.GroupNameTooLong()
		user = self.user
		detail = user.detail
		assert detail is not None
		group = Group(_gen_group_id(detail), name)
		detail.groups[group.id] = group
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if add_to_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			group_ab = ABGroup(group.id, group.name, False)
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'groups': [group_ab] }, user)
		return group
	
	def me_group_remove(self, group_id: str, *, remove_from_ab: bool = False) -> None:
		updated_ab_ctcs = []
		
		if group_id == '0':
			raise error.CannotRemoveSpecialGroup()
		user = self.user
		detail = user.detail
		assert detail is not None
		try:
			del detail.groups[group_id]
		except KeyError:
			raise error.GroupDoesNotExist()
		for ctc in detail.contacts.values():
			groups_old = ctc.groups.copy()
			ctc.groups.discard(group_id)
			if groups_old != ctc.groups and remove_from_ab:
				updated_ab_ctcs.append(ABContact(
					'Regular', ctc.head.uuid, ctc.head.email, ctc.status.name, ctc.groups, {},
					is_messenger_user = True,
				))
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if remove_from_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'contacts': updated_ab_ctcs, }, user)
			self.backend.user_service.delete_ab_group('00000000-0000-0000-0000-000000000000', group_id, user)
	
	def me_group_edit(self, group_id: str, new_name: str, *, disregard_name_limit: bool = False, add_to_ab: bool = False) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		g = detail.groups.get(group_id)
		if g is None:
			raise error.GroupDoesNotExist()
		if new_name is not None:
			if len(new_name) > MAX_GROUP_NAME_LENGTH and not disregard_name_limit:
				raise error.GroupNameTooLong()
			g.name = new_name
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if add_to_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			group_ab = ABGroup(g.id, g.name, False)
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'groups': [group_ab], }, user)
	
	def me_ab_group_edit(self, ab_groups: List[ABGroup]) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		if '00000000-0000-0000-0000-000000000000' not in detail.subscribed_ab_stores:
			# TODO: raise exception for SOAP services
			return
		
		self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'groups': ab_groups, }, user)
		for ab_group in ab_groups:
			for group in detail.groups.values():
				if group.id == ab_group.id and group.name != ab_group.name:
					group.name = ab_group.name
		self.backend._mark_modified(user, message_temp = self.message_temp)
	
	def me_group_contact_add(self, group_id: str, contact_uuid: str, *, add_to_ab: bool = False) -> None:
		if group_id == '0': return
		user = self.user
		detail = user.detail
		assert detail is not None
		if group_id not in detail.groups:
			raise error.GroupDoesNotExist()
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id in ctc.groups:
			raise error.ContactAlreadyOnList()
		ctc.groups.add(group_id)
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if add_to_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			ctc_ab = ABContact(
				'Regular', ctc.head.uuid, ctc.head.email, ctc.status.name, ctc.groups, {},
				is_messenger_user = True,
			)
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab], }, user)
	
	def me_group_contact_remove(self, group_id: str, contact_uuid: str, *, remove_from_ab: bool = False) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id not in detail.groups and group_id != '0':
			raise error.GroupDoesNotExist()
		try:
			ctc.groups.remove(group_id)
		except KeyError:
			if group_id == '0':
				raise error.ContactNotOnList()
		self.backend._mark_modified(user, message_temp = self.message_temp)
		if remove_from_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			ctc_ab = ABContact(
				'Regular', ctc.head.uuid, ctc.head.email, ctc.status.name, ctc.groups, {},
				is_messenger_user = True,
			)
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab], }, user)
	
	def me_subscribe_ab(self, ab_id: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		
		if ab_id in detail.subscribed_ab_stores:
			# TODO: raise exception for SOAP services
			return
		ab_subscribe = self.backend.user_service.check_ab(ab_id)
		if ab_subscribe:
			detail.subscribed_ab_stores.add(ab_id)
			self.backend._mark_modified(user, message_temp = self.message_temp)
	
	def other_subscribe_ab(self, ab_id: str, head: User) -> None:
		other_sess = backend.util_get_sessions_by_user(head)
		if other_sess:
			other_last_sess = other_sess[-1]
			other_last_sess.me_subscribe_ab(ab_id)
		else:
			backend.user_service.set_ab_subscription(head.uuid, ab_id)
	
	def me_contact_add(self, contact_uuid: str, lst: Lst, *, trid: Optional[str] = None, name: Optional[str] = None, message: Optional[TextWithData] = None, group_id: Optional[str] = None, adder_id: Optional[str] = None, needs_notify: bool = False, add_to_ab: bool = False) -> Tuple[Contact, User]:
		backend = self.backend
		ctc_head = backend._load_user_record(contact_uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		user = self.user
		ctc_status = ctc_head.status.substatus
		ctc = self._add_to_list(user, ctc_head, lst, name, add_to_ab, group_id)
		if lst & Lst.FL:
			# FL needs a matching RL on the contact
			ctc_me = self._add_to_list(ctc_head, user, Lst.RL, user.email, False, None)
			# `ctc_head` was added to `user`'s RL
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				#if sess_added is self: continue
				sess_added.evt.on_added_me(user, message = message, adder_id = adder_id)
		if ((lst & Lst.AL or lst & Lst.BL) and ctc.lists & Lst.RL) or needs_notify:
			for sess_added in backend._sc.get_sessions_by_user(ctc_head):
				if sess_added is self: continue
				sess_added.evt.on_presence_notification(user, (ctc_status if lst & Lst.BL else Substatus.Offline), False, visible_notif = False, send_status_on_bl = True, updated_phone_info = {
					'PHH': user.settings.get('PHH'),
					'PHW': user.settings.get('PHW'),
					'PHM': user.settings.get('PHM'),
					'MOB': user.settings.get('MOB'),
				})
		return ctc, ctc_head
	
	def me_ab_contact_edit(self, ab_contacts: List[ABContact], ab_id: str) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		if ab_id not in detail.subscribed_ab_stores:
			# TODO: raise exception for SOAP services
			return
		
		self.backend.user_service.mark_ab_modified(ab_id, { 'contacts': ab_contacts }, user)
		if ab_id == '00000000-0000-0000-0000-000000000000':
			for ab_contact in ab_contacts:
				ctc = detail.contacts.get(ab_contact.uuid)
				if ctc is None: continue
				if ctc.groups != ab_contact.groups:
					ctc.groups = ab_contact.groups
				if ctc.status.name != ab_contact.name:
					ctc.status.name = ab_contact.name
			self.backend._mark_modified(user, message_temp = self.message_temp)
	
	def me_contact_rename(self, contact_uuid: str, new_name: str, *, add_to_ab: bool = False) -> None:
		user = self.user
		detail = user.detail
		assert detail is not None
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		
		if len(new_name) > 387:
			raise error.NicknameExceedsLengthLimit()
		
		ctc.status.name = new_name
		self.backend._mark_modified(user, message_temp = self.message_temp)
		
		if add_to_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			ctc_ab = self.backend.user_service.ab_get_entry('00000000-0000-0000-0000-000000000000', ctc.head.uuid, user)
			if ctc_ab is not None:
				ctc_ab.name = new_name
				self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab] }, user)
	
	def me_contact_remove(self, contact_uuid: str, lst: Lst, *, group_id: Optional[str] = None, remove_from_ab: bool = False) -> None:
		backend = self.backend
		user = self.user
		detail = user.detail
		assert detail is not None
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None: 
			raise error.ContactDoesNotExist()
		assert not lst & Lst.RL
		self._remove_from_list(user, ctc.head, lst, group_id, remove_from_ab)
		if lst & Lst.FL:
			# Remove matching RL
			self._remove_from_list(ctc.head, user, Lst.RL, None, remove_from_ab)
		self.evt.on_sync_contact_statuses()
		if lst & Lst.BL:
			for sess_added in backend._sc.get_sessions_by_user(ctc.head):
				if sess_added is self: continue
				sess_added.evt.on_presence_notification(user, Substatus.Offline, False, updated_phone_info = {
					'PHH': user.settings.get('PHH'),
					'PHW': user.settings.get('PHW'),
					'PHM': user.settings.get('PHM'),
					'MOB': user.settings.get('MOB'),
				})
	
	def me_contact_deny(self, adder_uuid: str, deny_message: Optional[str], *, adder_id: Optional[str] = None):
		user_adder = self.backend._load_user_record(adder_uuid)
		if user_adder is None:
			raise error.UserDoesNotExist()
		user = self.user
		for sess_adder in self.backend._sc.get_sessions_by_user(user_adder):
			sess_adder.evt.on_contact_request_denied(user, deny_message or '', adder_id = adder_id)
	
	def _add_to_list(self, user: User, ctc_head: User, lst: Lst, name: Optional[str], add_to_ab: bool, group_id: Optional[str]) -> Contact:
		# Add `ctc` to `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		
		updated = False
		ab_updated = False
		duplicate_list = False
		
		if ctc_head.uuid not in contacts:
			contacts[ctc_head.uuid] = Contact(ctc_head, set(), Lst.Empty, UserStatus(name))
			updated = True
		ctc = contacts[ctc_head.uuid]
		
		if (ctc.lists & lst) != lst:
			ctc.lists |= lst
			updated = True
		else:
			if lst == Lst.FL and group_id is not None:
				if group_id in ctc.groups:
					raise error.ContactAlreadyOnList()
		
		orig_name = ctc.status.name
		if name is not None and (ctc.status.name is None or orig_name != name):
			ctc.status.name = name
			updated = True
			if ctc.lists & Lst.FL:
				ab_updated = True
		
		if lst == Lst.FL:
			ab_updated = True
			if group_id is not None:
				try:
					self.me_group_contact_add(group_id, ctc_head.uuid, add_to_ab = add_to_ab)
				except Exception as ex:
					raise ex
		
		if updated:
			self.backend._mark_modified(user, message_temp = self.message_temp, detail = detail)
			self.evt.on_sync_contact_statuses()
		if add_to_ab and ab_updated and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
			ctc_ab = ABContact(
				'Regular', ctc.head.uuid, ctc.head.email, ctc.status.name, ctc.groups, {},
				is_messenger_user = True,
			)
			self.backend.user_service.mark_ab_modified('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab] }, user)
		
		return ctc
	
	def _remove_from_list(self, user: User, ctc_head: User, lst: Lst, group_id: Optional[str], remove_from_ab: bool) -> None:
		# Remove `ctc_head` from `user`'s `lst`
		detail = self.backend._load_detail(user)
		contacts = detail.contacts
		ctc = contacts.get(ctc_head.uuid)
		if ctc is None: return
		
		updated = False
		if ctc.lists & lst:
			if lst == Lst.FL and group_id is not None:
				try:
					self.me_group_contact_remove(group_id, ctc.head.uuid, remove_from_ab = remove_from_ab)
				except Exception as ex:
					raise ex
				updated = True
				
			if (lst == Lst.FL and group_id is None) or not lst & Lst.FL:
				ctc.lists &= ~lst
				if lst == Lst.FL:
					ctc.groups = set()
					if remove_from_ab and '00000000-0000-0000-0000-000000000000' in detail.subscribed_ab_stores:
						if self.backend.user_service.ab_get_entry('00000000-0000-0000-0000-000000000000', ctc_head.uuid, user):
							self.backend.user_service.ab_delete_entry('00000000-0000-0000-0000-000000000000', ctc_head.uuid, user)
				updated = True
		
		if not ctc.lists:
			del contacts[ctc_head.uuid]
			updated = True
		
		if updated:
			self.backend._mark_modified(user, message_temp = self.message_temp, detail = detail)
			self.evt.on_sync_contact_statuses()
	
	def me_contact_notify_oim(self, uuid: str, oim_uuid: str) -> None:
		ctc_head = self.backend._load_user_record(uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		
		for sess_notify in self.backend._sc.get_sessions_by_user(ctc_head):
			if sess_notify is self: continue
			sess_notify.evt.msn_on_oim_sent(uuid)
	
	def me_send_uun_invitation(self, uuid: str, type: int, data: bytes, *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
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
	__slots__ = ('ids', 'backend', 'front_data', '_users_by_sess', 'idle_mins', '_idle_counter_reset_callback', '_stats')
	
	ids: Dict[str, str]
	backend: Backend
	front_data: Dict[str, Any]
	_users_by_sess: Dict['ChatSession', Tuple[User, str]]
	idle_mins: int
	_idle_counter_reset_callback: Optional[Callable]
	_stats: Any
	
	def __init__(self, backend: Backend, stats: Any) -> None:
		super().__init__()
		self.ids = {}
		self.backend = backend
		self.front_data = {}
		self._users_by_sess = {}
		self.idle_mins = 0
		self._idle_counter_reset_callback = None
		self._stats = stats
		
		self.add_id('main', backend.auth_service.GenTokenStr(trim = 10))
	
	def add_id(self, scope: str, id: str):
		assert id not in self.backend._chats_by_id
		self.ids[scope] = id
		self.backend._chats_by_id[(scope, id)] = self
	
	def join(self, origin: str, bs: BackendSession, evt: event.ChatEventHandler, *, preferred_name: Optional[str] = None, pop_id: Optional[str] = None) -> 'ChatSession':
		for user, _ in self._users_by_sess.values():
			if bs.user is user and origin is not 'yahoo': raise error.AuthFail()
		cs = ChatSession(origin, bs, self, evt, preferred_name = preferred_name)
		cs.evt.cs = cs
		self._users_by_sess[cs] = (cs.user, pop_id)
		if self._idle_counter_reset_callback is not None:
			self._idle_counter_reset_callback()
		cs.evt.on_open()
		return cs
	
	def add_session(self, sess: 'ChatSession', pop_id: Optional[str] = None) -> None:
		self._users_by_sess[sess] = (sess.user, pop_id)
	
	def get_roster(self) -> Iterable['ChatSession']:
		return self._users_by_sess.keys()
	
	def send_participant_joined(self, cs: 'ChatSession') -> None:
		for cs_other in self.get_roster():
			if cs_other is cs and cs.origin is 'yahoo': continue
			cs_other.evt.on_participant_joined(cs)
	
	def on_leave(self, sess: 'ChatSession', keep_future: bool, idle: bool, send_idle_leave: bool) -> None:
		last_pop = True
		su = self._users_by_sess.pop(sess, None)
		if su is None: return
		if self._idle_counter_reset_callback is not None and self._users_by_sess:
			self._idle_counter_reset_callback()
		# TODO: If it goes down to only 1 connected user,
		# the chat and remaining session(s) should be automatically closed.
		if not self._users_by_sess and not keep_future:
			for scope_id in self.ids.items():
				del self.backend._chats_by_id[scope_id]
			return
		sess_other_users = [sess_other_user for _, (sess_other_user, _) in self._users_by_sess.items() if sess_other_user.uuid == su[0].uuid]
		if len(sess_other_users) > 0:
			last_pop = False
		# Notify others that `sess` has left
		if (idle and send_idle_leave) or not idle:
			for sess1, _ in self._users_by_sess.items():
				if sess1 is sess: continue
				sess1.evt.on_participant_left(sess, idle, last_pop)

class ChatSession(Session):
	__slots__ = ('origin', 'user', 'chat', 'bs', 'evt', 'preferred_name')
	
	origin: Optional[str]
	user: User
	chat: Chat
	bs: BackendSession
	evt: event.ChatEventHandler
	preferred_name: Optional[str]
	
	def __init__(self, origin: str, bs: BackendSession, chat: Chat, evt: event.ChatEventHandler, *, preferred_name: Optional[str] = None) -> None:
		super().__init__()
		self.origin = origin
		self.user = bs.user
		self.chat = chat
		self.bs = bs
		self.evt = evt
		self.preferred_name = preferred_name
	
	def _on_close(self, *, keep_future: bool = False, idle: bool = False, send_idle_leave: bool = False) -> None:
		self.evt.on_close(keep_future, idle)
		self.chat.on_leave(self, keep_future, idle, send_idle_leave)
	
	def invite(self, invitee: User, *, invite_msg: Optional[str] = None) -> None:
		session_already_invited = False # type: bool
		already_invited_sessions = [] # type: List[BackendSession]
		
		ctc_sessions = self.bs.backend.util_get_sessions_by_user(invitee)
		for ctc_sess in ctc_sessions:
			session_already_invited = False
			for cs_other in self.chat.get_roster():
				if cs_other.bs is ctc_sess and self.origin is not 'yahoo':
					session_already_invited = True
					already_invited_sessions.append(ctc_sess)
					break
			if session_already_invited: continue
			ctc_sess.evt.on_chat_invite(self.chat, self.user, invite_msg = invite_msg or '')
		
		if len(ctc_sessions) == len(already_invited_sessions): raise error.ContactAlreadyOnList()
	
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
	while s in detail.groups:
		id += 1
		s = str(id)
	return s

MAX_GROUP_NAME_LENGTH = 61
