from typing import Dict, List, Optional, Any, Iterator
import json
from contextlib import contextmanager
from datetime import datetime, timedelta
import time
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from util import hash
from util.json_type import JSONType
import settings

def Col(*args: Any, **kwargs: Any) -> sa.Column:
	if 'nullable' not in kwargs:
		kwargs['nullable'] = False
	return sa.Column(*args, **kwargs)

class Base(declarative_base()): # type: ignore
	__abstract__ = True

class WithFrontData(Base):
	__abstract__ = True
	
	# Data specific to front-ends; e.g. different types of password hashes
	# E.g. front_data = { 'msn': { ... }, 'ymsg': { ... }, ... }
	_front_data = Col(JSONType, name = 'front_data', default = {})
	
	def set_front_data(self, frontend: str, key: str, value: Any) -> None:
		fd = self._front_data or {}
		if frontend not in fd:
			fd[frontend] = {}
		fd[frontend][key] = value
		# As a side-effect, this also makes `._front_data` into a new object,
		# so SQLAlchemy picks up the fact that it's been changed.
		# (SQLAlchemy only does shallow comparisons on fields by default.)
		self._front_data = _simplify_json_data(fd)
	
	def get_front_data(self, frontend: str, key: str) -> Any:
		fd = self._front_data
		if not fd: return None
		fd = fd.get(frontend)
		if not fd: return None
		return fd.get(key)

class User(WithFrontData):
	__tablename__ = 't_user'
	
	id = Col(sa.Integer, primary_key = True)
	date_created = Col(sa.DateTime, default = datetime.utcnow)
	date_login = Col(sa.DateTime, nullable = True)
	uuid = Col(sa.String, unique = True)
	email = Col(sa.String)
	verified = Col(sa.Boolean)
	name = Col(sa.String, nullable = True)
	message = Col(sa.String)
	password = Col(sa.String)
	groups = Col(JSONType)
	settings = Col(JSONType)

class UserContact(WithFrontData):
	__tablename__ = 't_user_contact'
	
	user_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	contact_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	user_uuid = Col(sa.String, sa.ForeignKey('t_user.uuid')) # = User(self.user_id).uuid
	
	uuid = Col(sa.String, sa.ForeignKey('t_user.uuid')) # = User(self.contact_id).uuid
	name = Col(sa.String)
	message = Col(sa.String)
	lists = Col(sa.Integer)
	pending = Col(sa.Boolean, default = False)
	groups = Col(JSONType)
	is_messenger_user = Col(sa.Boolean)
	
	index_id = Col(sa.String)
	birthdate = Col(sa.DateTime, nullable = True)
	anniversary = Col(sa.DateTime, nullable = True)
	notes = Col(sa.String, nullable = True)
	first_name = Col(sa.String, nullable = True)
	middle_name = Col(sa.String, nullable = True)
	last_name = Col(sa.String, nullable = True)
	nickname = Col(sa.String, nullable = True)
	primary_email_type = Col(sa.String, nullable = True)
	personal_email = Col(sa.String, nullable = True)
	work_email = Col(sa.String, nullable = True)
	im_email = Col(sa.String, nullable = True)
	other_email = Col(sa.String, nullable = True)
	home_phone = Col(sa.String, nullable = True)
	work_phone = Col(sa.String, nullable = True)
	fax_phone = Col(sa.String, nullable = True)
	pager_phone = Col(sa.String, nullable = True)
	mobile_phone = Col(sa.String, nullable = True)
	other_phone = Col(sa.String, nullable = True)
	personal_website = Col(sa.String, nullable = True)
	business_website = Col(sa.String, nullable = True)
	# locations = { '000-000': { 'name': "Foo", 'city': 'Bar' } }
	locations = Col(JSONType, default = {})

class GroupChat(Base):
	__tablename__ = 't_group_chat'
	
	id = Col(sa.Integer, primary_key = True)
	chat_id = Col(sa.String, unique = True)
	name = Col(sa.String)
	owner_id = Col(sa.String, sa.ForeignKey('t_user.id'))
	owner_uuid = Col(sa.String, sa.ForeignKey('t_user.uuid'))
	owner_friendly = Col(sa.String)
	membership_access = Col(sa.Integer)
	request_membership_option = Col(sa.Integer)
	# memberships = { '000-000': { 'role': 'GroupChatRole', 'state': 'CircleState', 'member_id': '000-000' }, ... }
	memberships = Col(JSONType)

def _simplify_json_data(data: Any) -> Any:
	if isinstance(data, dict):
		d = {}
		for k, v in data.items():
			v = _simplify_json_data(v)
			if v is not None:
				d[k] = v
		if not d:
			return None
		return d
	if isinstance(data, (list, tuple)):
		return [_simplify_json_data(x) for x in data]
	return data

engine = sa.create_engine(settings.DB)
session_factory = sessionmaker(bind = engine)

@contextmanager
def Session() -> Iterator[Any]:
	if Session._depth > 0: # type: ignore
		yield Session._global # type: ignore
		return
	session = session_factory()
	Session._global = session # type: ignore
	Session._depth += 1 # type: ignore
	try:
		yield session
		session.commit()
	except:
		session.rollback()
		raise
	finally:
		session.close()
		Session._global = None # type: ignore
		Session._depth -= 1 # type: ignore
Session._global = None # type: ignore
Session._depth = 0 # type: ignore
