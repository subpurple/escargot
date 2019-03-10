from datetime import datetime
from typing import Dict, Optional, Callable, Set, List, Any, TypeVar
from enum import Enum, IntEnum, IntFlag
import time

class User:
	__slots__ = ('uuid', 'email', 'verified', 'status', 'detail', 'settings', 'date_created')
	
	uuid: str
	email: str
	verified: bool
	status: 'UserStatus'
	detail: Optional['UserDetail']
	settings: Dict[str, Any]
	date_created: datetime
	
	def __init__(self, uuid: str, email: str, verified: bool, status: 'UserStatus', settings: Dict[str, Any], date_created: datetime) -> None:
		self.uuid = uuid
		self.email = email
		self.verified = verified
		# `status`: true status of user
		self.status = status
		self.detail = None
		self.settings = settings
		self.date_created = date_created

class Contact:
	__slots__ = ('head', '_groups', 'lists', 'status')
	
	head: User
	_groups: Set['ContactGroupEntry']
	lists: 'Lst'
	status: 'UserStatus'
	
	def __init__(self, user: User, groups: Set['ContactGroupEntry'], lists: 'Lst', status: 'UserStatus') -> None:
		self.head = user
		self._groups = groups
		self.lists = lists
		# `status`: status as known by the contact
		self.status = status
	
	def compute_visible_status(self, to_user: User) -> None:
		# Set Contact.status based on BLP and Contact.lists
		# If not blocked, Contact.status == Contact.head.status
		if self.head.detail is None or _is_blocking(self.head, to_user):
			self.status.substatus = Substatus.Offline
			return
		true_status = self.head.status
		self.status.substatus = true_status.substatus
		self.status.name = true_status.name
		self.status.set_status_message(true_status.message)
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

class ContactGroupEntry:
	__slots__ = ('contact_uuid', 'id', 'uuid')
	
	contact_uuid: str
	id: str
	uuid: str
	
	def __init__(self, contact_uuid: str, id: str, uuid: str) -> None:
		self.contact_uuid = contact_uuid
		self.id = id
		self.uuid = uuid

class ABContact:
	__slots__ = ('type', 'uuid', 'email', 'birthdate', 'anniversary', 'member_uuid', 'date_last_modified', 'notes', 'name', 'first_name', 'middle_name', 'last_name', 'primary_email_type', 'personal_email', 'work_email', 'im_email', 'other_email', 'home_phone', 'work_phone', 'fax_phone', 'pager_phone', 'mobile_phone', 'other_phone', 'personal_website', 'business_website', 'locations', 'groups', 'is_messenger_user', 'networkinfos', 'annotations')
	
	type: str
	uuid: str
	email: str
	birthdate: Optional[datetime]
	anniversary: Optional[datetime]
	member_uuid: Optional[str]
	date_last_modified: datetime
	notes: Optional[str]
	name: Optional[str]
	first_name: Optional[str]
	middle_name: Optional[str]
	last_name: Optional[str]
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
	locations: Dict[str, 'ABContactLocation']
	groups: Set[str]
	is_messenger_user: bool
	networkinfos: Dict['NetworkID', 'NetworkInfo']
	annotations: Dict[str, Any]
	
	def __init__(self, type: str, uuid: str, email: str, name: Optional[str], groups: Set[str], *, birthdate: Optional[datetime] = None, anniversary: Optional[datetime] = None, notes: Optional[str] = None, first_name: Optional[str] = None, middle_name: Optional[str] = None, last_name: Optional[str] = None, primary_email_type: Optional[str] = None, personal_email: Optional[str] = None, work_email: Optional[str] = None, im_email: Optional[str] = None, other_email: Optional[str] = None, home_phone: Optional[str] = None, work_phone: Optional[str] = None, fax_phone: Optional[str] = None, pager_phone: Optional[str] = None, mobile_phone: Optional[str] = None, other_phone: Optional[str] = None, personal_website: Optional[str] = None, business_website: Optional[str] = None, locations: Optional[Dict[str, 'ABContactLocation']] = None, networkinfos: Optional[Dict['NetworkID', 'NetworkInfo']] = None, member_uuid: Optional[str] = None, is_messenger_user: Optional[bool] = None, annotations: Optional[Dict[str, Any]] = None, date_last_modified: Optional[datetime] = None) -> None:
		self.type = type
		self.uuid = uuid
		self.email = email
		self.birthdate = birthdate
		self.anniversary = anniversary
		self.member_uuid = member_uuid
		self.date_last_modified = _default_if_none(date_last_modified, datetime.utcnow())
		self.notes = notes
		self.name = name
		self.first_name = first_name
		self.middle_name = middle_name
		self.last_name = last_name
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
		self.locations = _default_if_none(locations, {})
		self.groups = groups
		self.is_messenger_user = _default_if_none(is_messenger_user, False)
		self.networkinfos = _default_if_none(networkinfos, {})
		self.annotations = _default_if_none(annotations, {})

class ABContactLocation:
	__slots__ = ('type', 'name', 'street', 'city', 'state', 'country', 'zip_code')
	
	type: str
	name: Optional[str]
	street: Optional[str]
	city: Optional[str]
	state: Optional[str]
	country: Optional[str]
	zip_code: Optional[str]
	
	def __init__(self, type: str, *, name: Optional[str] = None, street: Optional[str] = None, city: Optional[str] = None, state: Optional[str] = None, country: Optional[str] = None, zip_code: Optional[str] = None) -> None:
		self.type = type
		self.name = name
		self.street = street
		self.city = city
		self.state = state
		self.country = country
		self.zip_code = zip_code

class NetworkInfo:
	__slots__ = ('domain_id', 'source_id', 'domain_tag', 'display_name', 'relationship_info', 'invite_message', 'date_created', 'date_last_modified')
	
	domain_id: 'NetworkID'
	source_id: str
	domain_tag: str
	display_name: Optional[str]
	relationship_info: 'RelationshipInfo'
	invite_message: Optional[str]
	date_created: datetime
	date_last_modified: datetime
	
	def __init__(self, domain_id: 'NetworkID', source_id: str, domain_tag: str, display_name: Optional[str], relationship_info: 'RelationshipInfo', *, invite_message: Optional[str] = None, date_created: Optional[datetime] = None, date_last_modified: Optional[datetime] = None) -> None:
		self.domain_id = domain_id
		self.source_id = source_id
		self.domain_tag = domain_tag
		self.display_name = display_name
		self.relationship_info = relationship_info
		self.invite_message = invite_message
		self.date_created = _default_if_none(date_created, datetime.utcnow())
		self.date_last_modified = _default_if_none(date_last_modified, datetime.utcnow())

class RelationshipInfo:
	__slots__ = ('relationship_type', 'relationship_role', 'relationship_state', 'relationship_state_date')
	
	relationship_type: 'ABRelationshipType'
	relationship_role: 'ABRelationshipRole'
	relationship_state: 'ABRelationshipState'
	relationship_state_date: datetime
	
	def __init__(self, relationship_type: 'ABRelationshipType', relationship_role: 'ABRelationshipRole', relationship_state: 'ABRelationshipState', relationship_state_date: Optional[datetime] = None) -> None:
		self.relationship_type = relationship_type
		self.relationship_role = relationship_role
		self.relationship_state = relationship_state
		self.relationship_state_date = _default_if_none(relationship_state_date, datetime.utcnow())

class UserStatus:
	__slots__ = ('substatus', 'name', '_message', '_persistent', 'media')
	
	substatus: 'Substatus'
	name: Optional[str]
	_message: str
	_persistent: bool
	media: Optional[Any]
	
	def __init__(self, name: Optional[str], message: str = '') -> None:
		self.substatus = Substatus.Offline
		self.name = name
		self._message = message
		self._persistent = True
		self.media = None
	
	@property
	def message(self) -> str:
		return self._message
	
	def set_status_message(self, message: str, *, persistent: bool = True) -> None:
		self._message = message
		self._persistent = persistent
	
	def is_offlineish(self) -> bool:
		return self.substatus.is_offlineish()

class UserDetail:
	__slots__ = ('subscribed_ab_stores', '_groups_by_id', '_groups_by_uuid', 'contacts')
	
	subscribed_ab_stores: Set[str]
	_groups_by_id: Dict[str, 'Group']
	_groups_by_uuid: Dict[str, 'Group']
	contacts: Dict[str, 'Contact']
	
	def __init__(self, subscribed_ab_stores: Set[str]) -> None:
		self.subscribed_ab_stores = subscribed_ab_stores
		self._groups_by_id = {}
		self._groups_by_uuid = {}
		self.contacts = {}
	
	def insert_group(self, grp: 'Group') -> None:
		self._groups_by_id[grp.id] = grp
		self._groups_by_uuid[grp.uuid] = grp
	
	def get_group_by_id(self, id: str) -> Optional['Group']:
		group = None
		
		group = self._groups_by_id.get(id)
		if group is None:
			group = self._groups_by_uuid.get(id)
		
		return group
	
	def get_groups_by_name(self, name: str) -> Optional[List['Group']]:
		groups = [] # type: List[Group]
		for group in self._groups_by_id.values():
			if group.name == name or (group.name.startswith(name) and len(group.name) > len(name) and group.name[len(group.name):].isnumeric()):
				if group not in groups: groups.append(group)
		for group in self._groups_by_uuid.values():
			if group.name == name or (group.name.startswith(name) and len(group.name) > len(name) and group.name[len(group.name):].isnumeric()):
				if group not in groups: groups.append(group)
		return groups or None
	
	def delete_group(self, grp: 'Group') -> None:
		if grp.id in self._groups_by_id:
			del self._groups_by_id[grp.id]
		if grp.uuid in self._groups_by_uuid:
			del self._groups_by_uuid[grp.uuid]

class Group:
	__slots__ = ('id', 'uuid', 'name', 'is_favorite', 'date_last_modified')
	
	id: str
	uuid: str
	name: str
	is_favorite: bool
	date_last_modified: datetime
	
	def __init__(self, id: str, uuid: str, name: str, is_favorite: bool, *, date_last_modified: Optional[datetime] = None) -> None:
		self.id = id
		self.uuid = uuid
		self.name = name
		self.is_favorite = is_favorite
		if date_last_modified is None:
			date_last_modified = datetime.utcnow()
		self.date_last_modified = date_last_modified

class MessageType(Enum):
	Chat = object()
	#CircleXML = object()
	Nudge = object()
	Typing = object()
	TypingDone = object()
	Webcam = object()

class MessageData:
	__slots__ = ('sender', 'type', 'text', 'front_cache')
	
	sender: User
	type: MessageType
	text: Optional[str]
	front_cache: Dict[str, Any]
	
	def __init__(self, *, sender: User, type: MessageType, text: Optional[str] = None) -> None:
		self.sender = sender
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

#class CircleMetadata:
#	__slots__ = ('circle_id', 'owner_email', 'owner_friendly', 'circle_name', 'date_last_modified', 'membership_access', 'request_membership_option', 'is_presence_enabled')
#	
#	circle_id: str
#	owner_email: str
#	owner_friendly: str
#	circle_name: str
#	date_last_modified: datetime
#	membership_access: int
#	request_membership_option: int
#	is_presence_enabled: bool
#	
#	def __init__(self, circle_id: str, owner_email: str, owner_friendly: str, circle_name: str, date_last_modified: datetime, membership_access: int, request_membership_option: int, is_presence_enabled: bool) -> None:
#		self.circle_id = circle_id
#		self.owner_email = owner_email
#		self.owner_friendly = owner_friendly
#		self.circle_name = circle_name
#		self.date_last_modified = date_last_modified
#		self.membership_access = membership_access
#		self.request_membership_option = request_membership_option
#		self.is_presence_enabled = is_presence_enabled
#
#class CircleMembership:
#	__slots__ = ('circle_id', 'email', 'role', 'state')
#	
#	circle_id: str
#	email: str
#	role: 'ABRelationshipRole'
#	state: 'ABRelationshipState'
#	
#	def __init__(self, circle_id: str, email: str, role: 'ABRelationshipRole', state: 'ABRelationshipState'):
#		self.circle_id = circle_id
#		self.email = email
#		self.role = role
#		self.state = state

class OIMMetadata:
	__slots__ = ('run_id', 'oim_num', 'from_member_name', 'from_member_friendly', 'to_member_name', 'last_oim_sent', 'oim_content_length')
	
	run_id: str
	oim_num: int
	from_member_name: str
	from_member_friendly: str
	to_member_name: str
	last_oim_sent: datetime
	oim_content_length: int
	
	def __init__(self, run_id: str, oim_num: int, from_member_name: str, from_member_friendly: str, to_member_name: str, last_oim_sent: datetime, oim_content_length: int) -> None:
		self.run_id = run_id
		self.oim_num = oim_num
		self.from_member_name = from_member_name
		self.from_member_friendly = from_member_friendly
		self.to_member_name = to_member_name
		self.last_oim_sent = last_oim_sent
		self.oim_content_length = oim_content_length

class YahooOIM:
	__slots__ = ('from_id', 'recipient_id', 'sent', 'message', 'utf8_kv')
	
	from_id: str
	recipient_id: str
	sent: datetime
	message: Optional[str]
	utf8_kv: Optional[bool]
	
	def __init__(self, from_id: str, recipient_id: str, sent: datetime, message: Optional[str], utf8_kv: Optional[bool]):
		self.from_id = from_id
		self.recipient_id = recipient_id
		self.sent = sent
		self.message = message
		self.utf8_kv = utf8_kv

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
		else:
			self.label = "Pending"
	
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

class ABRelationshipRole(IntEnum):
	Empty = 0
	Admin = 1
	AssistantAdmin = 2
	Member = 3
	StatePendingOutbound = 4

class ABRelationshipState(IntEnum):
	Empty = 0
	WaitingResponse = 1
	Left = 2
	Accepted = 3
	Rejected = 4

class ABRelationshipType(IntEnum):
	Regular = 3
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
