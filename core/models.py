from datetime import datetime
from typing import Dict, Optional, Set, List, Tuple, Any, TypeVar
from enum import Enum, IntEnum, IntFlag

class User:
	__slots__ = ('id', 'uuid', 'email', 'username', 'verified', 'status', 'detail', 'settings', 'date_created')
	
	id: int
	uuid: str
	email: str
	username: str
	verified: bool
	status: 'UserStatus'
	detail: Optional['UserDetail']
	settings: Dict[str, Any]
	date_created: datetime
	
	def __init__(
		self, id: int, uuid: str, email: str, username: str, verified: bool, status: 'UserStatus',
		settings: Dict[str, Any], date_created: datetime,
	) -> None:
		self.id = id
		self.uuid = uuid
		self.email = email
		self.username = username
		self.verified = verified
		# `status`: true status of user
		self.status = status
		self.detail = None
		self.settings = settings
		self.date_created = date_created

class Contact:
	__slots__ = ('head', '_groups', 'lists', 'status', 'is_messenger_user', 'pending', 'detail')
	
	head: User
	_groups: Set['ContactGroupEntry']
	lists: 'Lst'
	status: 'UserStatus'
	is_messenger_user: bool
	pending: bool
	detail: 'ContactDetail'
	
	def __init__(
		self, user: User, groups: Set['ContactGroupEntry'], lists: 'Lst', status: 'UserStatus', detail: 'ContactDetail', *,
		is_messenger_user: Optional[bool] = None, pending: Optional[bool] = None,
	) -> None:
		self.head = user
		self._groups = groups
		self.lists = lists
		# `status`: status as known by the contact
		self.status = status
		self.is_messenger_user = _default_if_none(is_messenger_user, True)
		self.pending = _default_if_none(pending, False)
		self.detail = detail
	
	def compute_visible_status(self, to_user: User) -> None:
		# Set Contact.status based on BLP and Contact.lists
		# If not blocked, Contact.status == Contact.head.status
		if self.head.detail is None or _is_blocking(self.head, to_user):
			self.status.substatus = Substatus.Offline
			return
		true_status = self.head.status
		self.status.substatus = true_status.substatus
		self.status.name = true_status.name
		self.status.message = true_status.message
		self.status.media = true_status.media
	
	def is_in_group_id(self, group_id: str) -> bool:
		for group in self._groups:
			if group.id == group_id:
				return True
		return False
	
	def group_in_entry(self, grp: 'Group') -> bool:
		for group in self._groups:
			if group.id == grp.id or group.uuid == grp.uuid:
				return True
		return False
	
	def add_group_to_entry(self, grp: 'Group') -> None:
		self._groups.add(ContactGroupEntry(
			self.head.uuid, grp.id, grp.uuid,
		))
	
	def remove_from_group(self, grp: 'Group') -> None:
		found_group = None
		for group in self._groups:
			if group.id == grp.id or group.uuid == grp.uuid:
				found_group = group
				break
		if found_group is not None:
			self._groups.discard(group)

def _is_blocking(blocker: User, blockee: User) -> bool:
	detail = blocker.detail
	assert detail is not None
	contact = detail.contacts.get(blockee.uuid)
	lists = (contact and contact.lists or 0)
	if lists & Lst.BL: return True
	if lists & Lst.AL: return False
	return (blocker.settings.get('BLP', 'AL') == 'BL')

class ContactDetail:
	__slots__ = (
		'index_id', 'birthdate', 'anniversary', 'notes', 'first_name', 'middle_name', 'last_name',
		'nickname', 'primary_email_type', 'personal_email', 'work_email', 'im_email', 'other_email',
		'home_phone', 'work_phone', 'fax_phone', 'pager_phone', 'mobile_phone', 'other_phone',
		'personal_website', 'business_website', 'locations',
	)
	
	index_id: str
	birthdate: Optional[datetime]
	anniversary: Optional[datetime]
	notes: Optional[str]
	first_name: Optional[str]
	middle_name: Optional[str]
	last_name: Optional[str]
	nickname: Optional[str]
	primary_email_type: Optional[str]
	personal_email: Optional[str]
	work_email: Optional[str]
	im_email: Optional[str]
	other_email: Optional[str]
	home_phone: Optional[str]
	work_phone: Optional[str]
	fax_phone: Optional[str]
	pager_phone: Optional[str]
	mobile_phone: Optional[str]
	other_phone: Optional[str]
	personal_website: Optional[str]
	business_website: Optional[str]
	locations: Dict[str, 'ContactLocation']
	
	def __init__(
		self, index_id: str, *, birthdate: Optional[datetime] = None, anniversary: Optional[datetime] = None,
		notes: Optional[str] = None, first_name: Optional[str] = None, middle_name: Optional[str] = None,
		last_name: Optional[str] = None, nickname: Optional[str] = None, primary_email_type: Optional[str] = None,
		personal_email: Optional[str] = None, work_email: Optional[str] = None, im_email: Optional[str] = None,
		other_email: Optional[str] = None, home_phone: Optional[str] = None, work_phone: Optional[str] = None,
		fax_phone: Optional[str] = None, pager_phone: Optional[str] = None, mobile_phone: Optional[str] = None,
		other_phone: Optional[str] = None, personal_website: Optional[str] = None, business_website: Optional[str] = None,
	):
		self.index_id = index_id
		self.birthdate = birthdate
		self.anniversary = anniversary
		self.notes = notes
		self.first_name = first_name
		self.middle_name = middle_name
		self.last_name = last_name
		self.nickname = nickname
		self.primary_email_type = primary_email_type
		self.personal_email = personal_email
		self.work_email = work_email
		self.im_email = im_email
		self.other_email = other_email
		self.home_phone = home_phone
		self.work_phone = work_phone
		self.fax_phone = fax_phone
		self.pager_phone = pager_phone
		self.mobile_phone = mobile_phone
		self.other_phone = other_phone
		self.personal_website = personal_website
		self.business_website = business_website
		self.locations = {}

class ContactGroupEntry:
	__slots__ = ('contact_uuid', 'id', 'uuid')
	
	contact_uuid: str
	id: str
	uuid: str
	
	def __init__(self, contact_uuid: str, id: str, uuid: str) -> None:
		self.contact_uuid = contact_uuid
		self.id = id
		self.uuid = uuid

class ContactLocation:
	__slots__ = ('type', 'name', 'street', 'city', 'state', 'country', 'zip_code')
	
	type: str
	name: Optional[str]
	street: Optional[str]
	city: Optional[str]
	state: Optional[str]
	country: Optional[str]
	zip_code: Optional[str]
	
	def __init__(
		self, type: str, *, name: Optional[str] = None, street: Optional[str] = None, city: Optional[str] = None,
		state: Optional[str] = None, country: Optional[str] = None, zip_code: Optional[str] = None,
	) -> None:
		self.type = type
		self.name = name
		self.street = street
		self.city = city
		self.state = state
		self.country = country
		self.zip_code = zip_code

class UserStatus:
	__slots__ = ('substatus', 'name', 'message', 'media')
	
	substatus: 'Substatus'
	name: str
	message: str
	media: Optional[Any]
	
	def __init__(self, name: str) -> None:
		self.substatus = Substatus.Offline
		self.name = name
		self.message = ''
		self.media = None
	
	def is_offlineish(self) -> bool:
		return self.substatus.is_offlineish()

class UserDetail:
	__slots__ = ('_groups_by_id', '_groups_by_uuid', 'contacts')
	
	_groups_by_id: Dict[str, 'Group']
	_groups_by_uuid: Dict[str, 'Group']
	contacts: Dict[str, 'Contact']
	
	def __init__(self) -> None:
		self._groups_by_id = {}
		self._groups_by_uuid = {}
		self.contacts = {}
	
	def get_contacts_by_list(self, lst: 'Lst') -> Tuple[Contact, ...]:
		return tuple([ctc for ctc in self.contacts.values() if ctc.lists & lst])
	
	def insert_group(self, grp: 'Group') -> None:
		self._groups_by_id[grp.id] = grp
		self._groups_by_uuid[grp.uuid] = grp
	
	def get_group_by_id(self, id: str) -> Optional['Group']:
		group = None
		
		group = self._groups_by_id.get(id)
		if group is None:
			group = self._groups_by_uuid.get(id)
		
		return group
	
	def get_groups_by_name(self, name: str) -> List['Group']:
		groups = [] # type: List[Group]
		for group in self._groups_by_id.values():
			if group.name == name:
				if group not in groups: groups.append(group)
		for group in self._groups_by_uuid.values():
			if group.name == name:
				if group not in groups: groups.append(group)
		return groups
	
	def delete_group(self, grp: 'Group') -> None:
		if grp.id in self._groups_by_id:
			del self._groups_by_id[grp.id]
		if grp.uuid in self._groups_by_uuid:
			del self._groups_by_uuid[grp.uuid]

class Group:
	__slots__ = ('id', 'uuid', 'name', 'is_favorite')
	
	id: str
	uuid: str
	name: str
	is_favorite: bool
	
	def __init__(self, id: str, uuid: str, name: str, is_favorite: bool) -> None:
		self.id = id
		self.uuid = uuid
		self.name = name
		self.is_favorite = is_favorite

class MessageType(Enum):
	Chat = object()
	Nudge = object()
	Typing = object()
	TypingDone = object()
	Webcam = object()

class MessageData:
	__slots__ = ('sender', 'sender_pop_id', 'type', 'text', 'front_cache')
	
	sender: User
	sender_pop_id: Optional[str]
	type: MessageType
	text: Optional[str]
	front_cache: Dict[str, Any]
	
	def __init__(self, *, sender: User, sender_pop_id: Optional[str] = None, type: MessageType, text: Optional[str] = None) -> None:
		self.sender = sender
		self.sender_pop_id = sender_pop_id
		self.type = type
		self.text = text
		self.front_cache = {}

class TextWithData:
	__slots__ = ('text', 'yahoo_utf8')
	
	text: str
	yahoo_utf8: Any
	
	def __init__(self, text: str, yahoo_utf8: Any) -> None:
		self.text = text
		self.yahoo_utf8 = yahoo_utf8

class RoamingInfo:
	__slots__ = ('name', 'name_last_modified', 'message', 'message_last_modified')
	
	name: Optional[str]
	name_last_modified: datetime
	message: Optional[str]
	message_last_modified: datetime
	
	def __init__(self, name: Optional[str], name_last_modified: datetime, message: Optional[str], message_last_modified: datetime) -> None:
		self.name = name
		self.name_last_modified = name_last_modified
		self.message = message
		self.message_last_modified = message_last_modified
		

class GroupChat:
	__slots__ = (
		'chat_id', 'name', 'owner_id', 'owner_uuid', 'owner_friendly', 'membership_access',
		'request_membership_option', 'memberships',
	)
	
	chat_id: str
	name: str
	owner_id: int
	owner_uuid: str
	owner_friendly: str
	membership_access: int
	request_membership_option: int
	memberships: Dict[str, 'GroupChatMembership']
	
	def __init__(
		self, chat_id: str, name: str, owner_id: int, owner_uuid: str, owner_friendly: str,
		membership_access: int, request_membership_option: int,
	) -> None:
		self.chat_id = chat_id
		self.name = name
		self.owner_id = owner_id
		self.owner_uuid = owner_uuid
		self.owner_friendly = owner_friendly
		self.membership_access = membership_access
		self.request_membership_option = request_membership_option
		self.memberships = {}

class GroupChatMembership:
	__slots__ = (
		'chat_id', 'head', 'role', 'state', 'blocking', 'inviter_uuid', 'inviter_email', 'inviter_name', 'invite_message',
	)
	
	chat_id: str
	head: User
	role: 'GroupChatRole'
	state: 'GroupChatState'
	blocking: bool
	inviter_uuid: Optional[str]
	inviter_email: Optional[str]
	inviter_name: Optional[str]
	invite_message: Optional[str]
	
	def __init__(
		self, chat_id: str, head: User, role: 'GroupChatRole', state: 'GroupChatState', *,
		blocking: bool = False, inviter_uuid: Optional[str] = None, inviter_email: Optional[str] = None,
		inviter_name: Optional[str] = None, invite_message: Optional[str] = None,
	):
		self.chat_id = chat_id
		self.head = head
		self.role = role
		self.state = state
		self.blocking = blocking
		self.inviter_uuid = inviter_uuid
		self.inviter_email = inviter_email
		self.inviter_name = inviter_name
		self.invite_message = invite_message

class OIM:
	__slots__ = (
		'uuid', 'run_id', 'from_email', 'from_username', 'from_friendly', 'from_friendly_encoding', 'from_friendly_charset',
		'from_user_id', 'to_email', 'sent', 'origin_ip', 'oim_proxy', 'headers', 'message', 'utf8',
	)
	
	uuid: str
	run_id: str
	from_email: str
	from_username: str
	from_friendly: str
	from_friendly_encoding: str
	from_friendly_charset: str
	from_user_id: Optional[str]
	to_email: str
	sent: datetime
	origin_ip: Optional[str]
	oim_proxy: Optional[str]
	headers: Dict[str, str]
	message: str
	utf8: bool
	
	def __init__(
		self, uuid: str, run_id: str, from_email: str, from_username: str, from_friendly: str, to_email: str, sent: datetime,
		message: str, utf8: bool, *, headers: Optional[Dict[str, str]] = None, from_friendly_encoding: Optional[str] = None,
		from_friendly_charset: Optional[str] = None, from_user_id: Optional[str] = None, origin_ip: Optional[str] = None,
		oim_proxy: Optional[str] = None,
	) -> None:
		self.uuid = uuid
		self.run_id = run_id
		self.from_email = from_email
		self.from_friendly = from_friendly
		self.from_friendly_encoding = _default_if_none(from_friendly_encoding, 'B')
		self.from_friendly_charset = _default_if_none(from_friendly_charset, 'utf-8')
		self.from_user_id = from_user_id
		self.to_email = to_email
		self.sent = sent
		self.origin_ip = origin_ip
		self.oim_proxy = oim_proxy
		self.headers = _default_if_none(headers, {})
		self.message = message
		self.utf8 = utf8

T = TypeVar('T')
def _default_if_none(x: Optional[T], default: T) -> T:
	if x is None: return default
	return x

class Substatus(Enum):
	Offline = object()
	Online = object()
	Busy = object()
	Idle = object()
	BRB = object()
	Away = object()
	OnPhone = object()
	OutToLunch = object()
	Invisible = object()
	NotAtHome = object()
	NotAtDesk = object()
	NotInOffice = object()
	OnVacation = object()
	SteppedOut = object()
	
	def is_offlineish(self) -> bool:
		return self is Substatus.Offline or self is Substatus.Invisible

class Lst(IntFlag):
	Empty = 0x00
	
	FL = 0x01
	AL = 0x02
	BL = 0x04
	RL = 0x08
	PL = 0x10
	
	label: str
	
	# TODO: This is ugly.
	def __init__(self, id: int) -> None:
		super().__init__()
		# From further discovery, `FL` isn't used officially in any of the membership SOAPs. Skip to `AL`.
		if id == 0x02:
			self.label = "Allow"
		elif id == 0x04:
			self.label = "Block"
		elif id == 0x08:
			self.label = "Reverse"
		elif id == 0x10:
			self.label = "Pending"
		else:
			self.label = "Undefined"
	
	@classmethod
	def Parse(cls, label: str) -> Optional['Lst']:
		if not hasattr(cls, '_MAP'):
			map = {}
			for lst in cls:
				map[lst.label.lower()] = lst
			setattr(cls, '_MAP', map)
		return getattr(cls, '_MAP').get(label.lower())

class NetworkID(IntEnum):
	# Official MSN types
	WINDOWS_LIVE = 0x01
	OFFICE_COMMUNICATOR = 0x02
	TELEPHONE = 0x04
	MNI = 0x08 # Mobile Network Interop, used by Vodafone
	CIRCLE = 0x09
	SMTP = 0x10 # Jaguire, Japanese mobile interop
	YAHOO = 0x20

class GroupChatRole(IntEnum):
	Empty = 0
	Admin = 1
	AssistantAdmin = 2
	Member = 3
	StatePendingOutbound = 4

class GroupChatState(IntEnum):
	Empty = 0
	WaitingResponse = 1
	Left = 2
	Accepted = 3
	Rejected = 4

class RelationshipType(IntEnum):
	Circle = 5

class Service:
	__slots__ = ('host', 'port')
	
	host: str
	port: int
	
	def __init__(self, host: str, port: int) -> None:
		self.host = host
		self.port = port

class LoginOption(Enum):
	BootOthers = object()
	NotifyOthers = object()
	Duplicate = object()
