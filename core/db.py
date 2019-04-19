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

class Base(declarative_base()): # type: ignore
	__abstract__ = True
	
	date_created = Col(sa.DateTime, nullable = True, default = datetime.utcnow)
	date_modified = Col(sa.DateTime, nullable = True, default = datetime.utcnow, onupdate = datetime.utcnow)

def Col(*args: Any, **kwargs: Any) -> sa.Column:
	if 'nullable' not in kwargs:
		kwargs['nullable'] = False
	return sa.Column(*args, **kwargs)

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
	date_login = Col(sa.DateTime, nullable = True)
	uuid = Col(sa.String, unique = True)
	email = Col(sa.String)
	relay = Col(sa.Boolean, default = False)
	verified = Col(sa.Boolean)
	name = Col(sa.String, nullable = True)
	message = Col(sa.String)
	password = Col(sa.String)
	settings = Col(JSONType)

class UserGroup(WithFrontData):
	__tablename__ = 't_user_group'
	
	id = Col(sa.Integer, primary_key = True)
	group_uuid = Col(sa.String) # TODO: unique, rename uuid
	
	user_id = Col(sa.Integer, sa.ForeignKey('t_user.id'))
	name = Col(sa.String)
	
	group_id = Col(sa.String) # TODO: MSN only?
	is_favorite = Col(sa.Boolean, default = False) # TODO: MSN only?

class UserContact(WithFrontData):
	__tablename__ = 't_user_contact'
	
	user_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	contact_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	uuid = Col(sa.String, unique = True)
	
	user_uuid = Col(sa.String) # = User(self.user_id).uuid
	contact_uuid = Col(sa.String) # = User(self.contact_id).uuid
	name = Col(sa.String)
	message = Col(sa.String)
	lists = Col(sa.Integer)
	groups = Col(JSONType)
	
	# TODO: Fields from AddressBookContact
	contact_id = Col(sa.String, nullable = True) # TODO: For yahoo, like group_id; need Unique(user_id, contact_id); needs new name
	type = Col(sa.String)
	email = Col(sa.String)
	birthdate = Col(sa.DateTime, nullable = True)
	anniversary = Col(sa.DateTime, nullable = True)
	notes = Col(sa.String)
	name = Col(sa.String)
	first_name = Col(sa.String)
	middle_name = Col(sa.String)
	last_name = Col(sa.String)
	nickname = Col(sa.String)
	primary_email_type = Col(sa.String)
	personal_email = Col(sa.String)
	work_email = Col(sa.String)
	im_email = Col(sa.String)
	other_email = Col(sa.String)
	home_phone = Col(sa.String)
	work_phone = Col(sa.String)
	fax_phone = Col(sa.String)
	pager_phone = Col(sa.String)
	mobile_phone = Col(sa.String)
	other_phone = Col(sa.String)
	personal_website = Col(sa.String)
	business_website = Col(sa.String)
	groups = Col(JSONType)
	is_messenger_user = Col(sa.Boolean, default = False)
	# annotations = { "Annotation.Name": "Value", ... }
	annotations = Col(JSONType, default = {})
	# locations = { '000-000': { 'name': "Foo", 'city': 'Bar' } }
	locations = Col(JSONType, default = {})

#class CircleStore(Base):
#	__tablename__ = 't_circle_store'
#	
#	id = Col(sa.Integer, primary_key = True)
#	circle_id = Col(sa.String, unique = True)
#	circle_name = Col(sa.String)
#	owner_email = Col(sa.String)
#	owner_friendly = Col(sa.String)
#	membership_access = Col(sa.Integer)
#	request_membership_option = Col(sa.Integer)
#	is_presence_enabled = Col(sa.Boolean)

#class CircleMembership(Base):
#	__tablename__ = 't_circle_membership'
#	
#	id = Col(sa.Integer, primary_key = True)
#	circle_id = Col(sa.String)
#	member_email = Col(sa.String)
#	member_role = Col(sa.Integer)
#	member_state = Col(sa.Integer)

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

class Sound(Base):
	__tablename__ = 't_sound'
	
	hash = Col(sa.String, primary_key = True)
	title = Col(sa.String)
	category = Col(sa.Integer)
	language = Col(sa.Integer)
	is_public = Col(sa.Boolean)

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
