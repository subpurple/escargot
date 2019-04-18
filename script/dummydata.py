from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from uuid import uuid4
import time

from util import misc
from core.models import Lst, NetworkID
from core.db import Base, Session, User, UserGroup, UserContact, AddressBook, AddressBookContact, AddressBookContactLocation, engine

from script.user import set_passwords

usercontacts_by_uuid_by_uuid = {} # type: Dict[str, Dict[str, UserContact]]
user_groups_by_uuid_by_uuid = {} # type: Dict[str, Dict[str, UserGroup]]
ab_contacts_by_uuid_by_uuid = {} # type: Dict[str, Dict[str, AddressBookContact]]

def main() -> None:
	U = []
	
	for domain in ['example.com', 'yahoo.com', 'hotmail.com', 'live.com']:
		d = domain[0]
		for i in range(1, 5 + 1):
			name = "T{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), '123456', name, "{} msg".format(name))
			usercontacts_by_uuid_by_uuid[user.uuid] = {}
			ab_contacts_by_uuid_by_uuid[user.uuid] = {}
			user_groups_by_uuid_by_uuid[user.uuid] = {}
			addressbook = create_addressbook(user.uuid)
			U.append((user, addressbook))
	
	for i in range(5):
		name = "Bot{}".format(i)
		user = create_user('{}@bot.log1p.xyz'.format(name.lower()), '123456', name, "{} msg".format(name))
		usercontacts_by_uuid_by_uuid[user.uuid] = {}
		ab_contacts_by_uuid_by_uuid[user.uuid] = {}
		user_groups_by_uuid_by_uuid[user.uuid] = {}
		addressbook = create_addressbook(user.uuid)
		U.append((user, addressbook))
	
	for i, (u, _) in enumerate(U):
		contacts_by_group: Dict[str, List[User]] = {}
		
		x = randomish(u)
		for j in range(x % 4):
			contacts_by_group["" if j == 0 else "U{}G{}".format(i, j)] = []
		group_names = list(contacts_by_group.keys())
		for uc, _ in U:
			y = x ^ randomish(uc)
			for k, group_name in enumerate(group_names):
				z = y ^ k
				if z % 2 < 1:
					contacts_by_group[group_name].append(uc)
		
		set_contacts(u, contacts_by_group)
	
	tables = []
	
	for u, ab_s in U:
		tables.append(u)
		tables.extend(usercontacts_by_uuid_by_uuid[u.uuid].values())
		tables.extend(user_groups_by_uuid_by_uuid[u.uuid].values())
		tables.extend(ab_contacts_by_uuid_by_uuid[u.uuid].values())
		ab_s.date_last_modified = datetime.utcnow()
		tables.append(ab_s)
	
	Base.metadata.create_all(engine)
	with Session() as sess:
		sess.query(User).delete()
		sess.query(UserGroup).delete()
		sess.query(UserContact).delete()
		sess.query(AddressBook).delete()
		sess.query(AddressBookContact).delete()
		sess.query(AddressBookContactLocation).delete()
		#sess.query(CircleStore).delete()
		#sess.query(CircleMembership).delete()
		sess.add_all(tables)

def create_user(email: str, pw: str, name: str, message: str) -> User:
	user = User(
		uuid = str(uuid4()), email = email, verified = True,
		name = name, message = message,
		settings = {}
	)
	# TODO: Should be generated on-demand, not here
	#ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
	#	datetime.utcnow().isoformat()[0:19] + 'Z', cid_format(user.uuid, decimal = True)
	#)
	#user.set_front_data('msn', 'circleticket', misc.sign_with_new_key_and_b64(ticketxml))
	set_passwords(user, pw, support_old_msn = True, support_yahoo = True)
	return user

def create_usercontact(user_uuid: str, uuid: str, name: str, message: str) -> UserContact:
	return UserContact(
		user_uuid = user_uuid, uuid = uuid,
		name = name, message = message,
		lists = Lst.Empty, groups = [],
	)

def create_usergroup(group_id: str, group_uuid: str, uuid: str, name: str) -> UserGroup:
	return UserGroup(
		user_uuid = uuid, group_id = group_id, group_uuid = group_uuid,
		name = name,
	)

def create_addressbook(uuid: str) -> AddressBook:
	return AddressBook(
		member_uuid = uuid,
	)

def create_addressbookcontact(contact_uuid: str, contact_id: str, uuid: str, email: str, name: str) -> AddressBookContact:
	return AddressBookContact(
		ab_origin_uuid = uuid, contact_id = contact_id, contact_uuid = str(uuid4()), contact_member_uuid = contact_uuid,
		type = 'Regular', email = email, name = name, groups = [],
		is_messenger_user = True, annotations = {},
	)

def set_contacts(user: User, contacts_by_group: Dict[str, List[User]]) -> None:
	user.contacts = {}
	user.groups = []
	
	contact_id = 2
	for i, (group_name, group_users) in enumerate(contacts_by_group.items()):
		group_id = str(i + 1)
		group_uuid = str(uuid4())
		if group_name:
			user_groups_by_uuid_by_uuid[user.uuid][group_id] = create_usergroup(group_id, group_uuid, user.uuid, group_name)
		for u in group_users:
			contact, contact_abs = add_contact_twosided(user, u, str(contact_id))
			if group_name:
				contact.groups.append({ 'id': group_id, 'uuid': group_uuid })
				assert contact_abs is not None
				contact_abs.groups.append(group_uuid)
				contact_abs.date_last_modified = datetime.utcnow()
			contact_id += 1

def randomish(u: User) -> int:
	return int(u.uuid[:8], 16)

def add_contact_twosided(user: User, user_contact: User, contact_id: str) -> Tuple[UserContact, Optional[AddressBookContact]]:
	contact, contact_abs = add_contact_onesided(user, user_contact, contact_id, Lst.AL | Lst.FL)
	add_contact_onesided(user_contact, user, None, Lst.RL)
	return contact, contact_abs

def add_contact_onesided(user: User, user_contact: User, contact_id: Optional[str], lst: Lst) -> Tuple[UserContact, Optional[AddressBookContact]]:
	if user_contact.uuid not in usercontacts_by_uuid_by_uuid[user.uuid]:
		usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid] = create_usercontact(user.uuid, user_contact.uuid, user_contact.name, user_contact.message)
	contact = usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid]
	contact.lists |= lst
	
	if user_contact.uuid not in ab_contacts_by_uuid_by_uuid[user.uuid] and lst & Lst.FL and contact_id is not None:
		ab_contacts_by_uuid_by_uuid[user.uuid][user_contact.uuid] = create_addressbookcontact(user_contact.uuid, contact_id, user.uuid, user_contact.email, user_contact.name)
	contact_abs = ab_contacts_by_uuid_by_uuid[user.uuid].get(user_contact.uuid)
	return contact, contact_abs

if __name__ == '__main__':
	main()
