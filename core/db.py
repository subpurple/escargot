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

def Col(t: sa.types.TypeEngine, **kwargs: Any) -> sa.Column:
	if 'nullable' not in kwargs:
		kwargs['nullable'] = False
	return sa.Column(t, **kwargs)

class User(Base):
	__tablename__ = 't_user'
	
	id = Col(sa.Integer, primary_key = True)
	date_created = Col(sa.DateTime, nullable = True, default = datetime.utcnow)
	date_login = Col(sa.DateTime, nullable = True)
	uuid = Col(sa.String, unique = True)
	email = Col(sa.String)
	relay = Col(sa.Boolean, default = False)
	verified = Col(sa.Boolean)
	name = Col(sa.String, nullable = True)
	message = Col(sa.String)
	password = Col(sa.String)
	settings = Col(JSONType)
	
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

class UserGroup(Base):
	__tablename__ = 't_user_group'
	
	id = Col(sa.Integer, primary_key = True)
	user_uuid = Col(sa.String)
	group_id = Col(sa.String)
	group_uuid = Col(sa.String)
	name = Col(sa.String)
	is_favorite = Col(sa.Boolean, default = False)
	date_last_modified = Col(sa.DateTime, nullable = True, default = datetime.utcnow)

class UserContact(Base):
	__tablename__ = 't_user_contact'
	
	id = Col(sa.Integer, primary_key = True)
	user_uuid = Col(sa.String)
	uuid = Col(sa.String)
	name = Col(sa.String, nullable = True)
	message = Col(sa.String, nullable = True)
	lists = Col(sa.Integer)
	groups = Col(JSONType)

class AddressBook(Base):
	__tablename__ = 't_addressbook'
	
	id = Col(sa.Integer, primary_key = True)
	member_uuid = Col(sa.String)
	date_created = Col(sa.DateTime, nullable = True, default = datetime.utcnow)
	date_last_modified = Col(sa.DateTime, nullable = True)

class AddressBookContact(Base):
	__tablename__ = 't_addressbook_contact'
	
	id = Col(sa.Integer, primary_key = True)
	ab_origin_uuid = Col(sa.String)
	contact_id = Col(sa.String)
	# `contact_uuid` is a UUID that identifies the contact in the addressbook; unrelated to the UUID of the contact's account
	# `contact_member_uuid` is the contact's account's UUID, indicating that the contact's a part of our network.
	contact_uuid = Col(sa.String)
	contact_member_uuid = Col(sa.String, nullable = True)
	date_last_modified = Col(sa.DateTime, nullable = True, default = datetime.utcnow)
	type = Col(sa.String)
	email = Col(sa.String)
	birthdate = Col(sa.DateTime, nullable = True)
	anniversary = Col(sa.DateTime, nullable = True)
	notes = Col(sa.String, nullable = True)
	name = Col(sa.String, nullable = True)
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
	groups = Col(JSONType)
	is_messenger_user = Col(sa.Boolean, default = False)
	# annotations = { "Annotation.Name": "Value", ... }
	annotations = Col(JSONType, default = {})

class AddressBookContactLocation(Base):
	__tablename__ = 't_addressbook_contact_location'
	
	id = Col(sa.Integer, primary_key = True)
	contact_uuid = Col(sa.String)
	ab_origin_uuid = Col(sa.String)
	location_type = Col(sa.String)
	name = Col(sa.String, nullable = True)
	street = Col(sa.String, nullable = True)
	city = Col(sa.String, nullable = True)
	state = Col(sa.String, nullable = True)
	country = Col(sa.String, nullable = True)
	zip_code = Col(sa.String, nullable = True)

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
#	date_last_modified = Col(sa.DateTime, default = datetime.now)

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
