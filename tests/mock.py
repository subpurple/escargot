from collections import deque
from typing import Deque, Dict, Any, List, Iterable, Tuple, Optional
from abc import ABCMeta
from datetime import datetime

import asyncio

from util.misc import gen_uuid
from core.auth import AuthService
from core.client import Client
from core.backend import BackendSession, _SessionCollection, Chat, GroupChat
from core import event
from core.models import User, Contact, UserDetail, Group, UserStatus, Lst, OIM, LoginOption, Substatus

class UserService:
	_user_by_uuid: Dict[str, User]
	_user_by_email: Dict[str, User]
	_detail_by_uuid: Dict[str, UserDetail]
	
	def __init__(self) -> None:
		self._user_by_uuid = {}
		self._user_by_email = {}
		self._detail_by_uuid = {}
		
		self._add_user('test1@example.com')
		self._add_user('test2@example.com')
	
	def _add_user(self, email: str) -> None:
		u = User(0, gen_uuid(), email, True, UserStatus(email), {}, datetime.utcnow())
		self._user_by_uuid[u.uuid] = u
		self._user_by_email[u.email] = u
		self._detail_by_uuid[u.uuid] = UserDetail()
	
	def update_date_login(self, uuid: str) -> None:
		pass
	
	def get_uuid(self, email: str) -> str:
		user = self._user_by_email.get(email)
		return user and user.uuid
	
	def get(self, uuid: str) -> User:
		return self._user_by_uuid.get(uuid)
	
	def get_detail(self, uuid: str) -> UserDetail:
		return self._detail_by_uuid.get(uuid)
	
	def get_oim_batch(self, user: User) -> List[OIM]:
		return []
	
	def save_batch(self, to_save: List[Tuple[User, UserDetail]]) -> None:
		for user, detail in to_save:
			assert detail is not None
			self._detail_by_uuid[user.uuid] = detail

class Stats:
	def __init__(self) -> None:
		pass
	
	def on_message_sent(self, user: User, client: Client) -> None:
		pass
	
	def on_user_active(self, user: User, client: Client) -> None:
		pass
	
	def on_message_received(self, user: User, client: Client) -> None:
		pass

class Backend:
	__slots__ = ('loop', 'user_service', 'auth_service', '_user_by_uuid', '_worklist_sync_db', '_worklist_notify', '_worklist_notify_self', '_stats', '_sc', '_chats_by_id', 'notify_maintenance', 'maintenance_mode')
	
	loop: asyncio.BaseEventLoop
	user_service: UserService
	auth_service: AuthService
	_user_by_uuid: Dict[str, User]
	_worklist_sync_db: Dict[User, UserDetail]
	_worklist_notify: Dict[str, Tuple[BackendSession, Optional[int], bool, Substatus, Optional[Dict[str, Any]], bool, bool]]
	_worklist_notify_self: Dict[str, BackendSession]
	_stats: Stats
	_sc: _SessionCollection
	_chats_by_id: Dict[Tuple[str, str], Chat]
	notify_maintenance: bool
	maintenance_mode: bool
	
	def __init__(self, user_service: UserService, auth_service: AuthService) -> None:
		self.loop = asyncio.get_event_loop()
		self.user_service = user_service
		self.auth_service = auth_service
		self._user_by_uuid = {}
		self._worklist_sync_db = {}
		self._worklist_notify = {}
		self._worklist_notify_self = {}
		self._stats = Stats()
		self._sc = _SessionCollection()
		self._chats_by_id = {}
		self.notify_maintenance = False
		self.maintenance_mode = False
		
		self.loop.create_task(self._worker_sync_db())
		self.loop.create_task(self._worker_notify())
		self.loop.create_task(self._worker_notify_self())
	
	def login(self, uuid: str, client: Client, evt: event.BackendEventHandler, *, option: Optional[LoginOption] = None, only_once: bool = False) -> Optional[BackendSession]:
		user = self._load_user_record(uuid)
		if user is None: return None
		
		bs = BackendSession(self, user, client, evt)
		bs.evt.bs = bs
		user.detail = self._load_detail(user)
		self._sc.add_session(bs)
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
	
	def chat_create(self, *, groupchat: Optional[GroupChat] = None) -> Chat:
		return Chat(self, self._stats, groupchat = groupchat)
	
	def chat_get(self, scope: str, id: str) -> Optional['Chat']:
		return self._chats_by_id.get((scope, id))
	
	def _mark_modified(self, user: User, *, detail: Optional[UserDetail] = None) -> None:
		ud = user.detail or detail
		if detail: assert ud is detail
		assert ud is not None
		self._worklist_sync_db[user] = ud
	
	def util_get_uuid_from_email(self, email: str) -> Optional[str]:
		return self.user_service.get_uuid(email)
	
	def util_set_sess_token(self, sess: BackendSession, token: str) -> None:
		pass
	
	def util_get_sessions_by_user(self, user: User) -> List[BackendSession]:
		return self._sc.get_sessions_by_user(user)
	
	async def _worker_sync_db(self) -> None:
		while True:
			await asyncio.sleep(1)
			self._sync_db_impl()
	
	def _sync_contact_statuses(self, user: User) -> None:
		detail = user.detail
		if detail is None: return
		for ctc in detail.contacts.values():
			if ctc.lists & Lst.FL:
				ctc.compute_visible_status(user)
			
			# If the contact lists ever become inconsistent (FL without matching RL),
			# the contact that's missing the RL will always see the other user as offline.
			# Because of this, and the fact that most contacts *are* two-way, and it
			# not being that much extra work, I'm leaving this line commented out.
			#if not ctc.lists & Lst.RL: continue
			
			if ctc.head.detail is None: continue
			ctc_rev = ctc.head.detail.contacts.get(user.uuid)
			if ctc_rev is None: continue
			ctc_rev.compute_visible_status(ctc.head)
	
	def _notify_self(self, bs: BackendSession) -> None:
		uuid = bs.user.uuid
		if uuid in self._worklist_notify_self:
			return
		self._worklist_notify_self[uuid] = bs
	
	def _notify_contacts(self, bs: BackendSession, old_substatus: Substatus, *, for_logout: bool = False, sess_id: Optional[int] = None, on_contact_add: bool = False, updated_phone_info: Optional[Dict[str, Any]] = None, update_status: bool = True) -> None:
		uuid = bs.user.uuid
		if uuid in self._worklist_notify:
			return
		
		self._worklist_notify[uuid] = (bs, sess_id, on_contact_add, old_substatus, updated_phone_info, update_status, for_logout)
	
	async def _worker_notify(self) -> None:
		# Notify relevant `BackendSession`s of status, name, message, media, etc. changes
		while True:
			await asyncio.sleep(0.2)
			self._notify_contacts_impl()
	
	def _notify_contacts_impl(self) -> None:
		worklist = self._worklist_notify
		try:
			for bs, sess_id, on_contact_add, old_substatus, updated_phone_info, update_status, for_logout in worklist.values():
				user = bs.user
				detail = user.detail
				assert detail is not None
				for ctc in detail.contacts.values():
					for bs_other in self._sc.get_sessions_by_user(ctc.head):
						if bs_other.user is user: continue
						detail_other = bs_other.user.detail
						if detail_other is None: continue
						ctc_me = detail_other.contacts.get(user.uuid)
						# This shouldn't be `None`, since every contact should have
						# an `RL` contact on the other users' list (at the very least).
						if ctc_me is None: continue
						if not ctc_me.lists & Lst.FL: continue
						bs_other.evt.on_presence_notification(bs, ctc_me, on_contact_add, old_substatus, sess_id = sess_id, update_status = update_status, updated_phone_info = updated_phone_info)
				#for groupchat in self.user_service.get_groupchat_batch(user):
				#	if groupchat.chat_id not in self._cses_by_bs_by_groupchat_id: continue
				#	if bs not in self._cses_by_bs_by_groupchat_id[groupchat.chat_id]: continue
				#	cs = self._cses_by_bs_by_groupchat_id[groupchat.chat_id][bs]
				#	assert cs is not None
				#	cs.chat.send_participant_status_updated(cs)
				#if user.status.substatus is Substatus.Offline:
				#	for cs_dict in self._cses_by_bs_by_groupchat_id.values():
				#		cs = cs_dict.pop(bs, None)
				#		if cs is not None:
				#			cs.close()
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

class Logger:
	def __init__(self, prefix: str, obj: object) -> None:
		pass
	
	def info(self, *args: Any) -> None:
		pass
	
	def error(self, exc: Exception) -> None:
		pass
	
	def log_connect(self) -> None:
		pass
	
	def log_disconnect(self) -> None:
		pass

DecodedMSNP = Tuple[Any, ...]

class MSNPWriter:
	__slots__ = ('_q',)
	
	_q: Deque[DecodedMSNP]
	
	def __init__(self) -> None:
		self._q = deque()
	
	def write(self, m: Iterable[Any]) -> None:
		self._q.append(tuple(str(x) for x in m if x is not None))
	
	def pop_message(self, *msg_expected: Any) -> DecodedMSNP:
		msg = self._q.popleft()
		assert len(msg) == len(msg_expected)
		for mi, mei in zip(msg, msg_expected):
			if mei is ANY: continue
			assert mi == str(mei)
		return msg
	
	def assert_empty(self) -> None:
		assert not self._q

class AnyCls:
	def __repr__(self) -> str: return '<ANY>'
ANY = AnyCls()
