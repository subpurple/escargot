from typing import Dict, List, Any, Tuple, Optional
from datetime import datetime
from uuid import uuid4
import time

from util import misc
from core.models import Lst, NetworkID
from core.db import Base, Session, User, UserGroup, UserContact, engine

from script.user import set_passwords

usercontacts_by_uuid_by_uuid = {} # type: Dict[str, Dict[str, UserContact]]
user_groups_by_uuid_by_uuid = {} # type: Dict[str, Dict[str, UserGroup]]

def main() -> None:
	U = []
	
	for domain in ['example.com', 'yahoo.com', 'hotmail.com', 'live.com']:
		d = domain[0]
		for i in range(1, 5 + 1):
			name = "T{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), '123456', name, "{} msg".format(name))
			usercontacts_by_uuid_by_uuid[user.uuid] = {}
			user_groups_by_uuid_by_uuid[user.uuid] = {}
			U.append(user)
	
	for i in range(5):
		name = "Bot{}".format(i)
		user = create_user('{}@bot.log1p.xyz'.format(name.lower()), '123456', name, "{} msg".format(name))
		usercontacts_by_uuid_by_uuid[user.uuid] = {}
		user_groups_by_uuid_by_uuid[user.uuid] = {}
		U.append(user)
	
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
		tables.append(ab_s)
	
	Base.metadata.create_all(engine)
	with Session() as sess:
		sess.query(User).delete()
		sess.query(UserGroup).delete()
		sess.query(UserContact).delete()
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

def set_contacts(user: User, contacts_by_group: Dict[str, List[User]]) -> None:
	user.contacts = {}
	user.groups = []
	
	yahoo_contact_id = 2
	for i, (group_name, group_users) in enumerate(contacts_by_group.items()):
		group_id = str(i + 1)
		group_uuid = str(uuid4())
		if group_name:
			user_groups_by_uuid_by_uuid[user.uuid][group_id] = create_usergroup(group_id, group_uuid, user.uuid, group_name)
		for u in group_users:
			contact = add_contact_twosided(user, u, str(yahoo_contact_id))
			if group_name:
				contact.groups.append({ 'id': group_id, 'uuid': group_uuid })
			yahoo_contact_id += 1

def create_usergroup(group_id: str, group_uuid: str, uuid: str, name: str) -> UserGroup:
	return UserGroup(
		user_uuid = uuid, group_id = group_id, group_uuid = group_uuid,
		name = name,
	)

def randomish(u: User) -> int:
	return int(u.uuid[:8], 16)

def add_contact_twosided(user: User, user_contact: User, yahoo_contact_id: str) -> UserContact:
	contact = add_contact_onesided(user, user_contact, yahoo_contact_id, Lst.AL | Lst.FL)
	add_contact_onesided(user_contact, user, None, Lst.RL)
	return contact

def add_contact_onesided(user: User, user_contact: User, yahoo_contact_id: Optional[str], lst: Lst) -> UserContact:
	if user_contact.uuid not in usercontacts_by_uuid_by_uuid[user.uuid]:
		usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid] = create_usercontact(user, user_contact, yahoo_contact_id)
	contact = usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid]
	contact.lists |= lst
	return contact

def create_usercontact(user: User, user_contact: User, yahoo_contact_id: Optional[str]) -> UserContact:
	return UserContact(
		user_id = user.id, user_uuid = user.uuid, contact_id = user_contact.id, contact_uuid = user_contact.uuid,
		uuid = str(uuid4()),
		name = user_contact.name, message = user_contact.message,
		lists = Lst.Empty, groups = [],
		
		# TODO: From AddressBookContact
		yahoo_contact_id = yahoo_contact_id,
		type = 'Regular', email = user_contact.email,
		is_messenger_user = True, annotations = {}, locations = {},
	)

if __name__ == '__main__':
	main()
