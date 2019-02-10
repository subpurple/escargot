from typing import Dict, List, Optional, Any
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

class User(Base):
	__tablename__ = 't_user'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	date_created = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)
	date_login = sa.Column(sa.DateTime, nullable = True)
	uuid = sa.Column(sa.String, nullable = False, unique = True)
	email = sa.Column(sa.String, nullable = False)
	relay = sa.Column(sa.Boolean, nullable = False, default = False)
	verified = sa.Column(sa.Boolean, nullable = False)
	name = sa.Column(sa.String, nullable = True)
	message = sa.Column(sa.String, nullable = False)
	password = sa.Column(sa.String, nullable = False)
	settings = sa.Column(JSONType, nullable = False)
	subscribed_ab_stores = sa.Column(JSONType, nullable = False)
	
	# Data specific to front-ends; e.g. different types of password hashes
	# E.g. front_data = { 'msn': { ... }, 'ymsg': { ... }, ... }
	_front_data = sa.Column(JSONType, name = 'front_data', nullable = False, default = {})
	
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
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	user_uuid = sa.Column(sa.String, nullable = False)
	group_id = sa.Column(sa.String, nullable = False)
	group_uuid = sa.Column(sa.String, nullable = False)
	name = sa.Column(sa.String, nullable = False)
	is_favorite = sa.Column(sa.Boolean, nullable = False, default = False)
	date_last_modified = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)

class UserContact(Base):
	__tablename__ = 't_user_contact'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	user_uuid = sa.Column(sa.String, nullable = False)
	uuid = sa.Column(sa.String, nullable = False)
	name = sa.Column(sa.String, nullable = True)
	message = sa.Column(sa.String, nullable = True)
	lists = sa.Column(sa.Integer, nullable = False)
	groups = sa.Column(JSONType, nullable = False)

class ABMetadata(Base):
	__tablename__ = 't_ab_metadata'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	ab_id = sa.Column(sa.String, nullable = False)
	ab_type = sa.Column(sa.String, nullable = False)

class ABStore(Base):
	__tablename__ = 't_ab_store'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	member_uuid = sa.Column(sa.String, nullable = False)
	ab_id = sa.Column(sa.String, nullable = False)
	date_created = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)
	date_last_modified = sa.Column(sa.DateTime, nullable = True)

class ABStoreContact(Base):
	__tablename__ = 't_ab_store_contact'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	ab_id = sa.Column(sa.String, nullable = False)
	ab_owner_uuid = sa.Column(sa.String, nullable = True)
	# `contact_uuid` is a UUID that identifies the contact in the addressbook; unrelated to the UUID of the contact's account
	# `contact_member_uuid` is the contact's account's UUID, indicating that the contact's a part of our network.
	contact_uuid = sa.Column(sa.String, nullable = False)
	contact_member_uuid = sa.Column(sa.String, nullable = True)
	date_last_modified = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)
	type = sa.Column(sa.String, nullable = False)
	email = sa.Column(sa.String, nullable = False)
	name = sa.Column(sa.String, nullable = True)
	groups = sa.Column(JSONType, nullable = False)
	is_messenger_user = sa.Column(sa.Boolean, nullable = False, default = False)
	annotations = sa.Column(JSONType, nullable = False)

#class ABStoreContactNetworkInfo(Base):
#	__tablename__ = 't_ab_store_contact_networkinfo'
#	
#	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
#	contact_uuid = sa.Column(sa.String, nullable = False)
#	ab_id = sa.Column(sa.String, nullable = False)
#	ab_owner_uuid = sa.Column(sa.String, nullable = True)
#	date_created = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)
#	date_last_modified = sa.Column(sa.DateTime, nullable = True, default = datetime.utcnow)
#	domain_id = sa.Column(sa.Integer, nullable = False)
#	source_id = sa.Column(sa.String, nullable = False)
#	domain_tag = sa.Column(sa.String, nullable = False)
#	display_name = sa.Column(sa.String, nullable = False)
#	relationship_type = sa.Column(sa.Integer, nullable = False)
#	relationship_role = sa.Column(sa.Integer, nullable = False)
#	relationship_state = sa.Column(sa.Integer, nullable = False)
#	relationship_state_date = sa.Column(sa.DateTime, nullable = True)
#	invite_message = sa.Column(sa.String, nullable = True)

#class CircleStore(Base):
#	__tablename__ = 't_circle_store'
#	
#	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
#	circle_id = sa.Column(sa.String, nullable = False, unique = True)
#	circle_name = sa.Column(sa.String, nullable = False)
#	owner_email = sa.Column(sa.String, nullable = False)
#	owner_friendly = sa.Column(sa.String, nullable = False)
#	membership_access = sa.Column(sa.Integer, nullable = False)
#	request_membership_option = sa.Column(sa.Integer, nullable = False)
#	is_presence_enabled = sa.Column(sa.Boolean, nullable = False)
#	date_last_modified = sa.Column(sa.DateTime, nullable = False, default = datetime.now)

#class CircleMembership(Base):
#	__tablename__ = 't_circle_membership'
#	
#	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
#	circle_id = sa.Column(sa.String, nullable = False)
#	member_email = sa.Column(sa.String, nullable = False)
#	member_role = sa.Column(sa.Integer, nullable = False)
#	member_state = sa.Column(sa.Integer, nullable = False)

class OIM(Base):
	__tablename__ = 't_oim'
	
	run_id = sa.Column(sa.String, nullable = False, unique = True, primary_key = True)
	oim_num = sa.Column(sa.Integer, nullable = False)
	from_member_name = sa.Column(sa.String, nullable = False)
	from_member_friendly = sa.Column(sa.String, nullable = False)
	to_member_name = sa.Column(sa.String, nullable = False)
	oim_sent = sa.Column(sa.DateTime, nullable = False)
	content = sa.Column(sa.String, nullable = False)
	is_read = sa.Column(sa.Boolean, nullable = False)

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

class YahooAlias(Base):
	__tablename__ = 't_yahoo_alias'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	yid_alias = sa.Column(sa.String, nullable = False)
	owner_uuid = sa.Column(sa.String, nullable = False)

class YahooOIM(Base):
	__tablename__ = 't_yahoo_oim'
	
	id = sa.Column(sa.Integer, nullable = False, primary_key = True)
	from_id = sa.Column(sa.String, nullable = False)
	recipient_id = sa.Column(sa.String, nullable = False)
	recipient_id_primary = sa.Column(sa.String, nullable = False)
	sent = sa.Column(sa.DateTime, nullable = False)
	message = sa.Column(sa.String, nullable = False)
	utf8_kv = sa.Column(sa.Boolean, nullable = True)

class Sound(Base):
	__tablename__ = 't_sound'
	
	hash = sa.Column(sa.String, nullable = False, primary_key = True)
	title = sa.Column(sa.String, nullable = False)
	category = sa.Column(sa.Integer, nullable = False)
	language = sa.Column(sa.Integer, nullable = False)
	is_public = sa.Column(sa.Boolean, nullable = False)

engine = sa.create_engine(settings.DB)
session_factory = sessionmaker(bind = engine)

@contextmanager
def Session():
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
