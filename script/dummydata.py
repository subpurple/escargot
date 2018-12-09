from typing import Dict, List, Any, Tuple, Optional
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import base64
from datetime import datetime
from uuid import uuid4
import time

from core.models import Lst, NetworkID
from core.db import Base, Session, User, ABStore, ABStoreContact, ABStoreGroup, ABMetadata, engine

from script.user import set_passwords
from front.msn.misc import cid_format

def main() -> None:
	U = []
	
	for domain in ['example.com', 'yahoo.com', 'hotmail.com', 'live.com']:
		d = domain[0]
		for i in range(1, 5 + 1):
			name = "T{}{}".format(i, d)
			user = create_user('{}@{}'.format(name.lower(), domain), '123456', name, "{} msg".format(name))
			abstore = create_abstore(user.uuid)
			U.append((user, abstore))
	
	for i in range(5):
		name = "Bot{}".format(i)
		user = create_user('{}@bot.log1p.xyz'.format(name.lower()), '123456', name, "{} msg".format(name))
		abstore = create_abstore(user.uuid)
		U.append((user, abstore))
	
	for i, (u, ab_s) in enumerate(U):
		contacts_by_group: Dict[str, List[User]] = {}
		
		x = randomish(u)
		for j in range(x % 4):
			contacts_by_group["" if j == 0 else "U{}G{}".format(i, j)] = []
		group_names = list(contacts_by_group.keys())
		for uc, uc_abs in U:
			y = x ^ randomish(uc)
			for k, group_name in enumerate(group_names):
				z = y ^ k
				if z % 2 < 1:
					contacts_by_group[group_name].append((uc, uc_abs))
		
		set_contacts(u, ab_s, contacts_by_group)
	
	tables = []
	
	for u, ab_s in U:
		u.contacts = list(u.contacts.values())
		tables.append(u)
		tables.extend(ab_s.groups.values())
		ab_s.groups = list(ab_s.groups.keys())
		tables.extend(ab_s.contacts.values())
		ab_s.contacts = list(ab_s.contacts.keys())
		tables.append(ab_s)
	
	Base.metadata.create_all(engine)
	with Session() as sess:
		sess.query(User).delete()
		sess.query(ABMetadata).delete()
		sess.query(ABStore).delete()
		sess.query(ABStoreContact).delete()
		sess.query(ABStoreGroup).delete()
		sess.add(ABMetadata(
			ab_id = '00000000-0000-0000-0000-000000000000', ab_type = 'Individual',
		))
		sess.add_all(tables)

def create_user(email: str, pw: str, name: str, message: str) -> User:
	user = User(
		uuid = str(uuid4()), networkid = NetworkID.ANY, email = email, verified = True,
		name = name, message = message,
		contacts = {}, groups = [],
		settings = {}, subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000'],
	)
	ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
		datetime.utcnow().isoformat()[0:19] + 'Z', cid_format(user.uuid, decimal = True)
	).encode('utf-8')
	user.set_front_data('msn', 'circleticket', [base64.b64encode(ticketxml).decode('ascii'), base64.b64encode(pkcs1_15.new(RSA.generate(2048)).sign(SHA1.new(ticketxml))).decode('ascii')])
	set_passwords(user, pw, support_old_msn = True, support_yahoo = True)
	return user

def create_abstore(uuid: str) -> ABStore:
	return ABStore(
		member_uuid = uuid, ab_id = '00000000-0000-0000-0000-000000000000',
		groups = {}, contacts = {},
	)

def create_abstorecontact(contact_uuid: str, uuid: str, email: str, name: str) -> ABStoreContact:
	return ABStoreContact(
		contact_uuid = contact_uuid, contact_owner_uuid = uuid,
		type = 'Regular', email = email, name = name, groups = [],
		is_messenger_user = True, annotations = {},
	)

def create_abstoregroup(group_id: str, uuid: str, name: str) -> ABStoreGroup:
	return ABStoreGroup(
		group_id = group_id, group_owner_uuid = uuid,
		name = name, is_favorite = False,
	)

def set_contacts(user: User, ab_store: ABStore, contacts_by_group: Dict[str, List[User]]) -> None:
	user.contacts = {}
	user.groups = []
	ab_store.contacts = {}
	ab_store.groups = {}
	
	for i, (group_name, group_users) in enumerate(contacts_by_group.items()):
		group_id = str(i + 1)
		if group_name:
			user.groups.append({ 'id': group_id, 'name': group_name })
			ab_store.groups[group_id] = create_abstoregroup(group_id, user.uuid, group_name)
		for u, ab_s in group_users:
			contact, contact_abs = add_contact_twosided((user, ab_store), (u, ab_s))
			if group_name:
				contact['groups'].append(group_id)
				contact_abs.groups.append(group_id)

def randomish(u: User) -> int:
	return int(u.uuid[:8], 16)

def add_contact_twosided(u_abs: Tuple[User, ABStore], c_abs: Tuple[User, ABStore]) -> Tuple[Dict[str, Any], Optional[ABStoreContact]]:
	contact, contact_abs = add_contact_onesided(u_abs[1], u_abs[0], c_abs[0], Lst.AL | Lst.FL)
	add_contact_onesided(c_abs[1], c_abs[0], u_abs[0], Lst.RL)
	return contact, contact_abs

def add_contact_onesided(ab_store: ABStore, user: User, user_contact: User, lst: Lst) -> Tuple[Dict[str, Any], Optional[ABStoreContact]]:
	if user_contact.uuid not in user.contacts:
		user.contacts[user_contact.uuid] = {
			'uuid': user_contact.uuid, 'name': user_contact.name,
			'message': user_contact.message, 'lists': Lst.Empty, 'groups': [],
		}
	contact = user.contacts[user_contact.uuid]
	contact['lists'] |= lst
	
	if user_contact.uuid not in ab_store.contacts and lst & Lst.FL:
		ab_store.contacts[user_contact.uuid] = create_abstorecontact(user_contact.uuid, user.uuid, user_contact.email, user_contact.name)
	contact_abs = ab_store.contacts.get(user_contact.uuid)
	return contact, contact_abs

if __name__ == '__main__':
	main()
