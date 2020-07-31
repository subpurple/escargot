from typing import List, Optional, Any
from datetime import datetime
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base

from util.json_type import JSONType

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
	username = Col(sa.String)
	verified = Col(sa.Boolean)
	# Roaming name - can be null and (in theory) stays constant to what the user sets it to
	name = Col(sa.String, nullable = True)
	name_last_modified = Col(sa.DateTime, default = datetime.utcnow)
	# Friendly name set during IM sessions. It cannot be null and is more prone to being overwritten than the roaming name
	friendly_name = Col(sa.String)
	# Roaming message
	message = Col(sa.String, nullable = True)
	message_last_modified = Col(sa.DateTime, default = datetime.utcnow)
	password = Col(sa.String)
	groups = Col(JSONType)
	settings = Col(JSONType)
	__table_args__ = (sa.Index('email_ci_index', sa.text('LOWER(email)'), unique = True), sa.Index('username_ci_index', sa.text('LOWER(username)'), unique = True))

class UserContact(WithFrontData):
	__tablename__ = 't_user_contact'
	
	user_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	contact_id = Col(sa.Integer, sa.ForeignKey('t_user.id'), primary_key = True)
	user_uuid = Col(sa.String, sa.ForeignKey('t_user.uuid')) # = User(self.user_id).uuid
	
	uuid = Col(sa.String, sa.ForeignKey('t_user.uuid')) # = User(self.contact_id).uuid
	name = Col(sa.String)
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
	owner_id = Col(sa.Integer, sa.ForeignKey('t_user.id'))
	owner_uuid = Col(sa.String, sa.ForeignKey('t_user.uuid'))
	owner_friendly = Col(sa.String)
	membership_access = Col(sa.Integer)
	request_membership_option = Col(sa.Integer)

class GroupChatMembership(Base):
	__tablename__ = 't_group_chat_membership'
	
	id = Col(sa.Integer, primary_key = True)
	chat_id = Col(sa.String, sa.ForeignKey('t_group_chat.chat_id'))
	member_id = Col(sa.Integer, sa.ForeignKey('t_user.id'))
	member_uuid = Col(sa.String, sa.ForeignKey('t_user.uuid'))
	role = Col(sa.Integer)
	state = Col(sa.Integer)
	blocking = Col(sa.Boolean)
	inviter_uuid = Col(sa.String, nullable = True)
	inviter_email = Col(sa.String, nullable = True)
	inviter_name = Col(sa.String, nullable = True)
	invite_message = Col(sa.String, nullable = True)

class LoginToken(Base):
	__tablename__ = 't_login_token'
	
	id = Col(sa.Integer, primary_key = True)
	token = Col(sa.String)
	purpose = Col(sa.String)
	data = Col(JSONType)
	expiry = Col(sa.DateTime)

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
