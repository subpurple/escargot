import asyncio
import pytest

from util.misc import gen_uuid
from core import db, stats
from core.conn import Conn
from core.auth import AuthService, LoginAuthService
from core.user import UserService
from core.backend import Backend
from core.models import User, Lst

@pytest.fixture
def backend_with_data(backend: Backend, conn: Conn) -> Backend:
	def _make_user(email: str, username: str) -> db.User:
		return db.User(
			uuid = gen_uuid(),
			email = email, username = username, verified = True,
			friendly_name = email, message = '', password = '',
			groups = {}, settings = {},
		)
	
	with conn.session() as sess:
		u1 = _make_user('test1@example.com', 'test1')
		u2 = _make_user('test2@example.com', 'test2')
		sess.add_all([u1, u2])
		sess.flush()
		c1 = db.UserContact(
			user_id = u1.id, user_uuid = u1.uuid, contact_id = u2.id, uuid = u2.uuid,
			name = u2.email, lists = Lst.FL,
			groups = {}, is_messenger_user = True, index_id = '0',
		)
		c2 = db.UserContact(
			user_id = u2.id, user_uuid = u2.uuid, contact_id = u1.id, uuid = u1.uuid,
			name = u1.email, lists = Lst.FL,
			groups = {}, is_messenger_user = True, index_id = '0',
		)
		sess.add_all([c1, c2])
	
	return backend

@pytest.fixture
def backend(conn: Conn) -> Backend:
	user_service = UserService(conn)
	auth_service = AuthService()
	login_auth_service = LoginAuthService(conn)
	stats_service = stats.Stats(conn)
	return Backend(
		asyncio.get_event_loop(),
		user_service = user_service, auth_service = auth_service, login_auth_service = login_auth_service,
		stats_service = stats_service,
	)

@pytest.fixture
def conn() -> Conn:
	conn = Conn('sqlite:///:memory:')
	db.Base.metadata.create_all(conn.engine)
	stats.Base.metadata.create_all(conn.engine)
	return conn
