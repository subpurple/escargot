from collections import deque
from typing import Deque, Dict, Any, List, Iterable, Tuple, Optional
import asyncio

from util.misc import gen_uuid
from core.conn import Conn
from core.auth import AuthService
from core.user import UserService
from core.stats import Stats
from core.client import Client
from core.backend import Backend
from core import event
from core.models import User, UserDetail, UserStatus, Lst
from front.msn.misc import MSNObj

def get_backend():
	from core import db, stats
	
	conn = Conn('sqlite:///:memory:')
	db.Base.metadata.create_all(conn.engine)
	stats.Base.metadata.create_all(conn.engine)
	
	def _make_user(email: str) -> None:
		return db.User(
			uuid = gen_uuid(),
			email = email, verified = True,
			message = '', password = '',
			groups = {}, settings = {},
		)
	
	with conn.session() as sess:
		u1 = _make_user('test1@example.com')
		u2 = _make_user('test2@example.com')
		sess.add_all([u1, u2])
		sess.flush()
		c1 = db.UserContact(
			user_id = u1.id, user_uuid = u1.uuid, contact_id = u2.id, uuid = u2.uuid,
			name = u2.email, message = u2.message, lists = Lst.FL,
			groups = {}, is_messenger_user = True, index_id = '0',
		)
		c2 = db.UserContact(
			user_id = u2.id, user_uuid = u2.uuid, contact_id = u1.id, uuid = u1.uuid,
			name = u1.email, message = u1.message, lists = Lst.FL,
			groups = {}, is_messenger_user = True, index_id = '0',
		)
		sess.add_all([c1, c2])
	
	user_service = UserService(conn)
	auth_service = AuthService()
	stats_service = Stats(conn)
	
	return Backend(
		asyncio.get_event_loop(),
		user_service = user_service, auth_service = auth_service,
		stats_service = stats_service,
	)

class Logger:
	def __init__(self, prefix: str, obj: object, front_debug: bool) -> None:
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
		self._q.append(tuple(str(x) for x in m if (not isinstance(x, MSNObj) and x is not None) or (isinstance(x, MSNObj) and x.data is not None)))
	
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
