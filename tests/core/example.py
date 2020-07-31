"""
	State, InEvents, and OutEvents
	
	Each InEvent maps State -> State', Set[OutEvent]
"""

from typing import List, Any, List, Dict, Iterable
import pytest

from util.misc import gen_uuid
from core.conn import Conn
from core.backend import Backend, BackendSession, ChatSession
from core.client import Client
from core.models import Lst
from core import db, event, models

@pytest.mark.xfail(raises = NotImplementedError)
def test_example(conn, backend):
	state = TState(conn, backend)
	
	u1 = state.do_create_user('u1@example.com', 'u1')
	u2 = state.do_create_user('u2@example.com', 'u2')
	
	s1 = u1.do_login()
	s2 = u2.do_login()
	
	# Calls the backend method for adding a contact,
	# and checks that u2 received a request
	cr = s1.do_add_contact(u2)
	
	# Accepts it, and checks that status notifications
	# get sent out
	s2.do_accept_contact_request(cr)
	
	# Makes the chat, checks that u1 gets an invite
	cs2 = s2.do_create_chat(u1)
	
	# Sends the message, checks that s1 receives it
	cs2.do_send_message("foo")

# Testing framework

class TState:
	def __init__(self, conn: Conn, backend: Backend) -> None:
		self.conn = conn
		self.backend = backend
		self._behs = []
		self._cehs = []
	
	def do_create_user(self, email: str, username: str) -> 'TUser':
		uuid = gen_uuid()
		with self.conn.session() as sess:
			db_user = db.User(
				uuid = uuid,
				email = email, username = username, verified = True,
				friendly_name = email, message = '', password = '',
				groups = {}, settings = {},
			)
			sess.add(db_user)
		self.assert_no_uncleared_events()
		return TUser(self, uuid, email)
	
	def _make_backend_event_handler(self) -> event.BackendEventHandler:
		beh = TBackendEventHandler()
		self._behs.append(beh)
		return beh
	
	def _make_chat_event_handler(self) -> event.ChatEventHandler:
		ceh = TChatEventHandler()
		self._cehs.append(ceh)
		return ceh
	
	def assert_no_uncleared_events(self) -> None:
		for evth in self._behs:
			assert not evth._events
	
	def get_user_beh(self, uuid: str) -> Iterable[Any]:
		for evt in self._behs:
			bs = evt.bs
			if bs is None:
				continue
			if bs.user.uuid != uuid:
				continue
			yield evt

class TBackendEventHandler:
	def __init__(self) -> None:
		self._events = []
	
	def _on_generic_event(self, name: str, args: List[Any], kwargs: Dict[str, Any]) -> None:
		self._events.append((name, args, kwargs))
	
	def assert_clear_events(self, events) -> None:
		assert self._events == events
		self._events.clear()
	
	def __getattr__(self, attr: str) -> Any:
		if not (attr.startswith('on_') or attr.startswith('msn_on') or attr.startswith('ymsg_on')):
			return None
		return lambda *args, **kwargs: self._on_generic_event(attr, args, kwargs)

class TChatEventHandler:
	def __init__(self) -> None:
		self._events = []
	
	def _on_generic_event(self, name: str, args: List[Any], kwargs: Dict[str, Any]) -> None:
		self._events.append((name, args, kwargs))
	
	def assert_clear_events(self, events) -> None:
		assert self._events == events
		self._events.clear()
	
	def __getattr__(self, attr: str) -> Any:
		if not attr.startswith('on_'):
			return None
		return lambda *args, **kwargs: self._on_generic_event(attr, args, kwargs)

class TUser:
	def __init__(self, state: TState, uuid: str, email: str) -> None:
		self.state = state
		self.backend = state.backend
		self.uuid = uuid
		self.email = email
	
	def do_login(self) -> 'TSession':
		client = Client('test', '0', 'direct')
		beh = self.state._make_backend_event_handler()
		bs = self.backend.login(self.uuid, client, beh)
		assert bs is not None
		beh.assert_clear_events([('on_open', (), {})])
		self.state.assert_no_uncleared_events()
		return TSession(self.state, bs, beh)

class TSession:
	def __init__(self, state: TState, bs: BackendSession, beh) -> None:
		self.state = state
		self.backend = state.backend
		self.bs = bs
		self.beh = beh
	
	def do_add_contact(self, other_user: Any) -> 'TContactRequest':
		if isinstance(other_user, TUser):
			uuid = other_user.uuid
		else:
			assert isinstance(other_user, str)
			assert '@' in other_user
			uuid = self.backend.util_get_uuid_from_email(other_user)
		assert uuid is not None
		self.bs.me_contact_add(uuid, Lst.FL)
		for other_user_evt in self.state.get_user_beh(uuid):
			other_user_evt.assert_clear_events([('on_added_me', (self.bs.user,), {
				'message': None,
				'adder_id': None,
			})])
		self.state.assert_no_uncleared_events()
		return TContactRequest(self.bs.user)
	
	def do_accept_contact_request(self, request: 'TContactRequest') -> 'TContact':
		self.bs.me_contact_add(request.user.uuid, Lst.AL)
		for other_user_evt in self.state.get_user_beh(request.user.uuid):
			for ctc in request.user.detail.contacts.values():
				if ctc.head is not self.bs.user:
					continue
				other_user_evt.assert_clear_events([('on_presence_notification', (ctc, False, models.Substatus.Offline), {
					'send_status_on_bl': False,
					'updated_phone_info': {'PHH': None, 'PHW': None, 'PHM': None, 'MOB': None},
				})])
		self.state.assert_no_uncleared_events()
		return TContact()
	
	def do_create_chat(self, contacts: List['Contact']) -> 'TChatSession':
		core_chat = self.backend.chat_create()
		ceh = self.state._make_chat_event_handler()
		core_chat_sess = core_chat.join('test', self.bs, ceh)
		self.state.assert_no_uncleared_events()
		return TChatSession(self.state, core_chat_sess)

class TContactRequest:
	def __init__(self, user: models.User) -> None:
		self.user = user

class TContact:
	pass

class TChatSession:
	def __init__(self, state: TState, cs: ChatSession) -> None:
		self.state = state
		self.backend = state.backend
		self.cs = cs
	
	def do_send_message(self, message: str) -> None:
		md = models.MessageData(sender = self.cs.user, type = models.MessageType.Chat, text = message)
		self.cs.send_message_to_everyone(md)
		raise NotImplementedError("TODO: check chat event handler events")
		self.state.assert_no_uncleared_events()
