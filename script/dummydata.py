from typing import Dict, List, Any, Tuple, Optional
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import base64
from datetime import datetime
from uuid import uuid4
import time

from core.models import Lst, NetworkID
from core.db import Base, Session, User, UserGroup, UserContact, ABStore, ABStoreContact, ABStoreContactNetworkInfo, ABMetadata, CircleStore, CircleMembership, OIM, YahooOIM, engine

from script.user import set_passwords
from front.msn.misc import cid_format

usercontacts_by_uuid_by_uuid = {}
user_groups_by_uuid_by_uuid = {}
ab_store_contacts_by_uuid_by_uuid = {}

def main() -> None:
	U = []
	
	for domain in ['example.com', 'yahoo.com', 'hotmail.com', 'live.com']:
		d = domain[0]
		for i in range(1, 5 + 1):
			name = "T{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), '123456', name, "{} msg".format(name))
			usercontacts_by_uuid_by_uuid[user.uuid] = {}
			ab_store_contacts_by_uuid_by_uuid[user.uuid] = {}
			user_groups_by_uuid_by_uuid[user.uuid] = {}
			abstore = create_abstore(user.uuid)
			U.append((user, abstore))
	
	for i in range(5):
		name = "Bot{}".format(i)
		user = create_user('{}@bot.log1p.xyz'.format(name.lower()), '123456', name, "{} msg".format(name))
		usercontacts_by_uuid_by_uuid[user.uuid] = {}
		ab_store_contacts_by_uuid_by_uuid[user.uuid] = {}
		user_groups_by_uuid_by_uuid[user.uuid] = {}
		abstore = create_abstore(user.uuid)
		U.append((user, abstore))
	
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
		tables.extend(ab_store_contacts_by_uuid_by_uuid[u.uuid].values())
		ab_s.date_last_modified = datetime.utcnow()
		tables.append(ab_s)
	
	Base.metadata.create_all(engine)
	with Session() as sess:
		sess.query(User).delete()
		sess.query(UserGroup).delete()
		sess.query(UserContact).delete()
		sess.query(ABMetadata).delete()
		sess.query(ABStore).delete()
		sess.query(ABStoreContact).delete()
		sess.query(ABStoreContactNetworkInfo).delete()
		sess.query(CircleStore).delete()
		sess.query(CircleMembership).delete()
		sess.query(OIM).delete()
		sess.query(YahooOIM).delete()
		sess.add(ABMetadata(
			ab_id = '00000000-0000-0000-0000-000000000000', ab_type = 'Individual',
		))
		sess.add_all(tables)

def create_user(email: str, pw: str, name: str, message: str) -> User:
	user = User(
		uuid = str(uuid4()), email = email, verified = True,
		name = name, message = message,
		settings = {}, subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000'],
	)
	ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
		datetime.utcnow().isoformat()[0:19] + 'Z', cid_format(user.uuid, decimal = True)
	).encode('utf-8')
	user.set_front_data('msn', 'circleticket', [base64.b64encode(ticketxml).decode('ascii'), base64.b64encode(pkcs1_15.new(RSA.generate(2048)).sign(SHA1.new(ticketxml))).decode('ascii')])
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

def create_abstore(uuid: str) -> ABStore:
	return ABStore(
		member_uuid = uuid, ab_id = '00000000-0000-0000-0000-000000000000',
	)

def create_abstorecontact(contact_uuid: str, uuid: str, email: str, name: str) -> ABStoreContact:
	return ABStoreContact(
		ab_id = '00000000-0000-0000-0000-000000000000', ab_owner_uuid = uuid, contact_uuid = str(uuid4()), contact_member_uuid = contact_uuid,
		type = 'Regular', email = email, name = name, groups = [],
		is_messenger_user = True, annotations = {},
	)

def set_contacts(user: User, contacts_by_group: Dict[str, List[User]]) -> None:
	user.contacts = {}
	user.groups = []
	
	for i, (group_name, group_users) in enumerate(contacts_by_group.items()):
		group_id = str(i + 1)
		group_uuid = str(uuid4())
		if group_name:
			user_groups_by_uuid_by_uuid[user.uuid][group_id] = create_usergroup(group_id, group_uuid, user.uuid, group_name)
		for u in group_users:
			contact, contact_abs = add_contact_twosided(user, u)
			if group_name:
				contact.groups.append({ 'id': group_id, 'uuid': group_uuid })
				contact_abs.groups.append(group_uuid)
				contact_abs.date_last_modified = datetime.utcnow()

def randomish(u: User) -> int:
	return int(u.uuid[:8], 16)

def add_contact_twosided(user: User, user_contact: User) -> Tuple[UserContact, Optional[ABStoreContact]]:
	contact, contact_abs = add_contact_onesided(user, user_contact, Lst.AL | Lst.FL)
	add_contact_onesided(user_contact, user, Lst.RL)
	return contact, contact_abs

def add_contact_onesided(user: User, user_contact: User, lst: Lst) -> Tuple[Dict[str, Any], Optional[ABStoreContact]]:
	if user_contact.uuid not in usercontacts_by_uuid_by_uuid[user.uuid]:
		usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid] = create_usercontact(user.uuid, user_contact.uuid, user_contact.name, user_contact.message)
	contact = usercontacts_by_uuid_by_uuid[user.uuid][user_contact.uuid]
	contact.lists |= lst
	
	if user_contact.uuid not in ab_store_contacts_by_uuid_by_uuid[user.uuid] and lst & Lst.FL:
		ab_store_contacts_by_uuid_by_uuid[user.uuid][user_contact.uuid] = create_abstorecontact(user_contact.uuid, user.uuid, user_contact.email, user_contact.name)
	contact_abs = ab_store_contacts_by_uuid_by_uuid[user.uuid].get(user_contact.uuid)
	return contact, contact_abs

if __name__ == '__main__':
	main()
