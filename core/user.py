from typing import Dict, Optional, List, Tuple, Set, Any, TYPE_CHECKING
from datetime import datetime
from urllib.parse import quote
from dateutil import parser as iso_parser
from pathlib import Path
import asyncio, traceback
import json

from util.hash import hasher, hasher_md5, hasher_md5crypt, gen_salt
from util import misc

from . import error
from .db import Session, User as DBUser, UserGroup as DBUserGroup, UserContact as DBUserContact, AddressBook as DBAddressBook, AddressBookContact as DBAddressBookContact, AddressBookContactLocation as DBAddressBookContactLocation
from .models import User, Contact, ContactGroupEntry, AddressBookContact, AddressBookContactLocation, UserStatus, UserDetail, NetworkID, Lst, Group, OIM, MessageData

if TYPE_CHECKING:
	from .backend import BackendSession

class UserService:
	loop: asyncio.AbstractEventLoop
	_cache_by_uuid: Dict[str, Optional[User]]
	_ab_ctc_cache_by_uuid_by_uuid: Dict[str, Dict[str, Optional[AddressBookContact]]]
	_worklist_sync_ab: Dict[int, Tuple[User, Dict[str, Any]]]
	_working_ab_sync_ids: List[int]
	
	def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
		self.loop = loop
		self._cache_by_uuid = {}
		self._ab_ctc_cache_by_uuid_by_uuid = {}
		self._worklist_sync_ab = {}
		self._working_ab_sync_ids = []
		
		loop.create_task(self._worker_sync_ab())
	
	def login(self, email: str, pwd: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email).one_or_none()
			if dbuser is None: return None
			if not hasher.verify(pwd, dbuser.password): return None
			return dbuser.uuid
	
	def msn_login_md5(self, email: str, md5_hash: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email).one_or_none()
			if dbuser is None: return None
			if not hasher_md5.verify_hash(md5_hash, dbuser.get_front_data('msn', 'pw_md5') or ''): return None
			return dbuser.uuid
	
	def msn_get_md5_salt(self, email: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email).one_or_none()
			if dbuser is None: return None
			pw_md5 = dbuser.get_front_data('msn', 'pw_md5')
		if pw_md5 is None: return None
		return hasher.extract_salt(pw_md5)
	
	def yahoo_get_md5_password(self, uuid: str) -> Optional[bytes]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return hasher_md5.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5_unsalted') or '')
	
	def yahoo_get_md5crypt_password(self, uuid: str) -> Optional[bytes]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return hasher_md5crypt.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5crypt') or '')
	
	def update_date_login(self, uuid: str) -> None:
		with Session() as sess:
			sess.query(DBUser).filter(DBUser.uuid == uuid).update({
				'date_login': datetime.utcnow(),
			})
	
	def is_user_relay(self, uuid: str) -> Optional[bool]:
		with Session() as sess:
			tmp = sess.query(DBUser.relay).filter(DBUser.uuid == uuid).one_or_none()
			if tmp is None: return None
			return tmp and tmp[0]
	
	#def msn_is_user_circle(self, uuid: str) -> Optional[bool]:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
	#		if dbuser is None: return None
	#		if dbuser.get_front_data('msn', 'circle') is True:
	#			return True
	#	return False
	
	def get_uuid(self, email: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email).one_or_none()
			if dbuser is None: return None
			#if dbuser.get_front_data('msn', 'circle') is True:
			#	return None
			return dbuser.uuid
	
	#def get_msn_circle_acc_uuid(self, circle_id: str) -> Optional[str]:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.email == '{}@live.com'.format(circle_id)).one_or_none()
	#		if dbuser is None: return None
	#		if not dbuser.get_front_data('msn', 'circle'):
	#			return None
	#		return dbuser.uuid
	
	def get(self, uuid: str) -> Optional[User]:
		if uuid not in self._cache_by_uuid:
			self._cache_by_uuid[uuid] = self._get_uncached(uuid)
		return self._cache_by_uuid[uuid]
	
	def _get_uncached(self, uuid: str) -> Optional[User]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			status = UserStatus(dbuser.name, dbuser.message)
			return User(dbuser.uuid, dbuser.email, dbuser.verified, status, dbuser.settings, dbuser.date_created)
	
	def get_detail(self, uuid: str) -> Optional[UserDetail]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			detail = UserDetail()
			groups = sess.query(DBUserGroup).filter(DBUserGroup.user_uuid == uuid)
			for g in groups:
				grp = Group(g.group_id, g.group_uuid, g.name, g.is_favorite, date_last_modified = g.date_last_modified)
				detail._groups_by_id[grp.id] = grp
				detail._groups_by_uuid[grp.uuid] = grp
			contacts = sess.query(DBUserContact).filter(DBUserContact.user_uuid == uuid)
			for c in contacts:
				ctc_head = self.get(c.uuid)
				if ctc_head is None: continue
				status = UserStatus(c.name, c.message)
				ctc_groups = set([ContactGroupEntry(
					c.uuid, group_entry['id'], group_entry['uuid'],
				) for group_entry in c.groups])
				ctc = Contact(
					ctc_head, ctc_groups, c.lists, status,
				)
				detail.contacts[ctc.head.uuid] = ctc
		return detail
	
	async def _worker_sync_ab(self) -> None:
		while True:
			await asyncio.sleep(1)
			self._sync_ab_impl()
	
	def _sync_ab_impl(self) -> None:
		if not self._worklist_sync_ab: return
		try:
			keys = list(self._worklist_sync_ab.keys())[:100]
			batch = []
			for key in keys:
				user, fields = self._worklist_sync_ab.pop(key)
				self._working_ab_sync_ids.append(key)
				batch.append((key,user,fields))
			self.save_batch_ab(batch)
		except:
			traceback.print_exc()
	
	def create_ab(self, user: User) -> None:
		with Session() as sess:
			dbaddressbook = sess.query(DBAddressBook).filter(DBAddressBook.member_uuid == user.uuid).one_or_none()
			
			if not dbaddressbook:
				dbaddressbook = DBAddressBook(
					member_uuid = user.uuid,
				)
				sess.add(dbaddressbook)
	
	def mark_ab_modified(self, fields: Dict[str, Any], user: User) -> int:
		id = len(self._worklist_sync_ab.keys())
		self._worklist_sync_ab[id] = (user, fields)
		return id
	
	async def mark_ab_modified_async(self, fields: Dict[str, Any], user: User) -> None:
		id = self.mark_ab_modified(fields, user)
		await asyncio.sleep(1)
		while id in self._working_ab_sync_ids:
			await asyncio.sleep(0.1)
	
	def ab_get_entry_by_uuid(self, ctc_uuid: str, user: User) -> Optional[AddressBookContact]:
		with Session() as sess:
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.contact_uuid == ctc_uuid, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			
			if dbaddressbookcontact is None:
				return None
			
			return self._ab_get_entry(dbaddressbookcontact.contact_uuid, user)
	
	def ab_get_entry_by_email(self, email: str, ctc_type: str, user: User) -> Optional[AddressBookContact]:
		with Session() as sess:
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.email == email, DBAddressBookContact.type == ctc_type, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			
			if dbaddressbookcontact is None:
				for user_other, fields in self._worklist_sync_ab.values():
					if user_other is user:
						for c in fields['contacts']:
							if c.email == email and c.type == ctc_type:
								return c
				return None
			
			return self._ab_get_entry(dbaddressbookcontact.contact_uuid, user)
	
	def ab_get_entry_by_id(self, ctc_id: str, user: User) -> Optional[AddressBookContact]:
		with Session() as sess:
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.contact_id == ctc_id, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			
			if dbaddressbookcontact is None:
				return None
			
			return self._ab_get_entry(dbaddressbookcontact.contact_uuid, user)
	
	def _ab_get_entry(self, contact_uuid: str, user: User) -> Optional[AddressBookContact]:
		ctc_ab = None
		
		if user.uuid in self._ab_ctc_cache_by_uuid_by_uuid:
			if contact_uuid in self._ab_ctc_cache_by_uuid_by_uuid[user.uuid]:
				ctc_ab = self._ab_ctc_cache_by_uuid_by_uuid[user.uuid][contact_uuid]
		
		if ctc_ab is None:
			if user.uuid not in self._ab_ctc_cache_by_uuid_by_uuid:
				self._ab_ctc_cache_by_uuid_by_uuid[user.uuid] = {}
			ctc_ab = self._ab_get_entry_uncached(contact_uuid, user)
		
		return ctc_ab
	
	def _ab_get_entry_uncached(self, contact_uuid: str, user: User) -> Optional[AddressBookContact]:
		head = None
		
		with Session() as sess:
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.contact_uuid == contact_uuid, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			
			if dbaddressbookcontact is None:
				return None
			
			if dbaddressbookcontact.contact_member_uuid is not None:
				head = self.get(dbaddressbookcontact.contact_member_uuid)
				if head is None: return None
			
			dbaddressbookcontactlocations = sess.query(DBAddressBookContactLocation).filter(DBAddressBookContactLocation.contact_uuid == dbaddressbookcontact.contact_uuid, DBAddressBookContactLocation.ab_origin_uuid == dbaddressbookcontact.ab_origin_uuid)
			locations = {
				dbaddressbookcontactlocation.location_type: AddressBookContactLocation(
					dbaddressbookcontactlocation.location_type, name = dbaddressbookcontactlocation.name, street = dbaddressbookcontactlocation.street, city = dbaddressbookcontactlocation.city, state = dbaddressbookcontactlocation.state, country = dbaddressbookcontactlocation.country, zip_code = dbaddressbookcontactlocation.zip_code,
			) for dbaddressbookcontactlocation in dbaddressbookcontactlocations}
			
			annotations = {} # type: Dict[Any, Any]
			for annots in dbaddressbookcontact.annotations:
				annotations.update(annots)
			addressbookcontact = AddressBookContact(
				dbaddressbookcontact.type, dbaddressbookcontact.contact_id, dbaddressbookcontact.contact_uuid, dbaddressbookcontact.email, dbaddressbookcontact.name, set(dbaddressbookcontact.groups),
				birthdate = dbaddressbookcontact.birthdate, anniversary = dbaddressbookcontact.anniversary, notes = dbaddressbookcontact.notes, first_name = dbaddressbookcontact.first_name, middle_name = dbaddressbookcontact.middle_name, last_name = dbaddressbookcontact.last_name, nickname = dbaddressbookcontact.nickname, home_phone = dbaddressbookcontact.home_phone, work_phone = dbaddressbookcontact.work_phone, fax_phone = dbaddressbookcontact.fax_phone, pager_phone = dbaddressbookcontact.pager_phone, mobile_phone = dbaddressbookcontact.mobile_phone, other_phone = dbaddressbookcontact.other_phone, personal_website = dbaddressbookcontact.personal_website, business_website = dbaddressbookcontact.business_website, locations = locations, primary_email_type = dbaddressbookcontact.primary_email_type, personal_email = dbaddressbookcontact.personal_email, work_email = dbaddressbookcontact.work_email, im_email = dbaddressbookcontact.im_email, other_email = dbaddressbookcontact.other_email, member_uuid = dbaddressbookcontact.contact_member_uuid, is_messenger_user = dbaddressbookcontact.is_messenger_user, annotations = annotations, date_last_modified = dbaddressbookcontact.date_last_modified,
			)
			self._ab_ctc_cache_by_uuid_by_uuid[user.uuid][contact_uuid] = addressbookcontact
			
			return addressbookcontact
	
	def get_ab_contents(self, user: User) -> Optional[Tuple[User, datetime, datetime, Dict[str, AddressBookContact]]]:
		with Session() as sess:
			dbaddressbook = self._get_ab_store(user.uuid)
			if dbaddressbook is None:
				return None
			
			head = self.get(dbaddressbook.member_uuid)
			if head is None: return None
			
			contacts = {}
			
			dbaddressbookcontacts = sess.query(DBAddressBookContact).filter(DBAddressBookContact.ab_origin_uuid == user.uuid)
			for dbaddressbookcontact in dbaddressbookcontacts:
				ctc = self._ab_get_entry(dbaddressbookcontact.contact_uuid, user)
				if ctc is None: continue
				contacts[dbaddressbookcontact.contact_uuid] = ctc
			return head, dbaddressbook.date_created, dbaddressbook.date_last_modified, contacts
	
	def ab_delete_entry(self, ctc_uuid: str, user: User) -> None:
		with Session() as sess:
			dbaddressbook = self._get_ab_store(user.uuid)
			if dbaddressbook is None:
				return None
			
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.contact_uuid == ctc_uuid, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			if dbaddressbookcontact is not None:
				if user.uuid in self._ab_ctc_cache_by_uuid_by_uuid:
					if dbaddressbookcontact.contact_uuid in self._ab_ctc_cache_by_uuid_by_uuid[user.uuid]:
						del self._ab_ctc_cache_by_uuid_by_uuid[user.uuid][dbaddressbookcontact.contact_uuid]
				
				dbaddressbookcontactlocations = sess.query(DBAddressBookContactLocation).filter(DBAddressBookContactLocation.contact_uuid == dbaddressbookcontact.contact_uuid, DBAddressBookContactLocation.ab_origin_uuid == dbaddressbookcontact.ab_origin_uuid)
				for dbaddressbookcontactlocation in dbaddressbookcontactlocations:
					sess.delete(dbaddressbookcontactlocation)
				sess.delete(dbaddressbookcontact)
				
				dbaddressbook.date_last_modified = datetime.utcnow()
				sess.add(dbaddressbook)
	
	def ab_delete_entry_by_email(self, email: str, ctc_type: str, user: User) -> None:
		with Session() as sess:
			dbaddressbook = self._get_ab_store(user.uuid)
			if dbaddressbook is None:
				return None
			
			dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.email == email, DBAddressBookContact.type == ctc_type, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
			if dbaddressbookcontact is not None:
				if user.uuid in self._ab_ctc_cache_by_uuid_by_uuid:
					if dbaddressbookcontact.contact_uuid in self._ab_ctc_cache_by_uuid_by_uuid[user.uuid]:
						del self._ab_ctc_cache_by_uuid_by_uuid[user.uuid][dbaddressbookcontact.contact_uuid]
				
				dbaddressbookcontactlocations = sess.query(DBAddressBookContactLocation).filter(DBAddressBookContactLocation.contact_uuid == dbaddressbookcontact.contact_uuid, DBAddressBookContactLocation.ab_origin_uuid == dbaddressbookcontact.ab_origin_uuid)
				for dbaddressbookcontactlocation in dbaddressbookcontactlocations:
					sess.delete(dbaddressbookcontactlocation)
				sess.delete(dbaddressbookcontact)
				
				dbaddressbook.date_last_modified = datetime.utcnow()
				sess.add(dbaddressbook)
	
	def gen_ab_entry_id(self, user: User) -> str:
		tpl = self.get_ab_contents(user)
		assert tpl is not None
		_, _, _, ab_contacts = tpl
		
		id = 2
		
		for i, _ in enumerate(ab_contacts):
			if i+2 == id:
				id += 1
				continue
		s = str(id)
		
		return s
	
	def save_batch_ab(self, batch: List[Tuple[int, User, Dict[str, Any]]]) -> None:
		with Session() as sess:
			for id, user, fields in batch:
				updated = False
				dbaddressbook = self._get_ab_store(user.uuid)
				if dbaddressbook is None:
					return None
				
				if 'contacts' in fields:
					for c in fields['contacts']:
						dbaddressbookcontact = sess.query(DBAddressBookContact).filter(DBAddressBookContact.contact_uuid == c.uuid, DBAddressBookContact.ab_origin_uuid == user.uuid).one_or_none()
						if dbaddressbookcontact is None:
							dbaddressbookcontact = DBAddressBookContact(
								ab_origin_uuid = user.uuid,
								contact_id = c.id, contact_uuid = c.uuid, contact_member_uuid = c.member_uuid, type = c.type, email = c.email, birthdate = c.birthdate, anniversary = c.anniversary, notes = c.notes, name = c.name, first_name = c.first_name, middle_name = c.middle_name, last_name = c.last_name, nickname = c.nickname, primary_email_type = c.primary_email_type, personal_email = c.personal_email, work_email = c.work_email, im_email = c.im_email, other_email = c.other_email, home_phone = c.home_phone, work_phone = c.work_phone, fax_phone = c.fax_phone, pager_phone = c.pager_phone, mobile_phone = c.mobile_phone, other_phone = c.other_phone, personal_website = c.personal_website, business_website = c.business_website, groups = list(c.groups), is_messenger_user = c.is_messenger_user, annotations = [{
									name: value
								} for name, value in c.annotations.items()],
							)
						else:
							dbaddressbookcontact.email = c.email
							dbaddressbookcontact.birthdate = c.birthdate
							dbaddressbookcontact.anniversary = c.anniversary
							dbaddressbookcontact.notes = c.notes
							dbaddressbookcontact.name = c.name
							dbaddressbookcontact.first_name = c.first_name
							dbaddressbookcontact.middle_name = c.middle_name
							dbaddressbookcontact.last_name = c.last_name
							dbaddressbookcontact.nickname = c.nickname
							dbaddressbookcontact.primary_email_type = c.primary_email_type
							dbaddressbookcontact.personal_email = c.personal_email
							dbaddressbookcontact.work_email = c.work_email
							dbaddressbookcontact.im_email = c.im_email
							dbaddressbookcontact.other_email = c.other_email
							dbaddressbookcontact.home_phone = c.home_phone
							dbaddressbookcontact.work_phone = c.work_phone
							dbaddressbookcontact.fax_phone = c.fax_phone
							dbaddressbookcontact.pager_phone = c.pager_phone
							dbaddressbookcontact.mobile_phone = c.mobile_phone
							dbaddressbookcontact.other_phone = c.other_phone
							dbaddressbookcontact.personal_website = c.personal_website
							dbaddressbookcontact.business_website = c.business_website
							dbaddressbookcontact.groups = list(c.groups)
							dbaddressbookcontact.is_messenger_user = c.is_messenger_user
							dbaddressbookcontact.annotations = [{
								name: value
							} for name, value in c.annotations.items()]
						
						dbaddressbookcontactlocations = sess.query(DBAddressBookContactLocation).filter(DBAddressBookContactLocation.contact_uuid == dbaddressbookcontact.contact_uuid, DBAddressBookContactLocation.ab_origin_uuid == dbaddressbookcontact.ab_origin_uuid)
						
						for dbaddressbookcontactlocation in dbaddressbookcontactlocations:
							if dbaddressbookcontactlocation.location_type not in c.locations:
								sess.delete(dbaddressbookcontactlocation)
						
						for location in c.locations.values():
							dbaddressbookcontactlocation = sess.query(DBAddressBookContactLocation).filter(DBAddressBookContactLocation.location_type == location.type, DBAddressBookContactLocation.contact_uuid == dbaddressbookcontact.contact_uuid, DBAddressBookContactLocation.ab_origin_uuid == dbaddressbookcontact.ab_origin_uuid).one_or_none()
							if dbaddressbookcontactlocation is None:
								dbaddressbookcontactlocation = DBAddressBookContactLocation(
									contact_uuid = dbaddressbookcontact.contact_uuid, ab_origin_uuid = user.uuid,
									location_type = location.type, name = location.name, street = location.street, city = location.city, state = location.state, country = location.country, zip_code = location.zip_code,
								)
							else:
								dbaddressbookcontactlocation.name = location.name
								dbaddressbookcontactlocation.street = location.street
								dbaddressbookcontactlocation.city = location.city
								dbaddressbookcontactlocation.state = location.state
								dbaddressbookcontactlocation.country = location.country
								dbaddressbookcontactlocation.zip_code = location.zip_code
							sess.add(dbaddressbookcontactlocation)
						
						dbaddressbookcontact.date_last_modified = datetime.utcnow()
						c.date_last_modified = dbaddressbookcontact.date_last_modified
						sess.add(dbaddressbookcontact)
					updated = True
				
				if updated:
					dbaddressbook.date_last_modified = datetime.utcnow()
					sess.add(dbaddressbook)
				self._working_ab_sync_ids.remove(id)
	
	def _get_ab_store(self, uuid: str) -> Optional[DBAddressBook]:
		with Session() as sess:
			dbaddressbook = sess.query(DBAddressBook).filter(DBAddressBook.member_uuid == uuid).one_or_none()
		
		return dbaddressbook
	
	#def msn_update_circleticket(self, uuid: str, cid: str) -> None:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
	#		if dbuser is not None:
	#			tik = self.msn_build_circleticket(uuid, cid)
	#			dbuser.set_front_data('msn', 'circleticket', tik)
	#			sess.add(dbuser)
	#
	#def msn_build_circleticket(self, uuid: str, cid: str) -> Optional[Tuple[str, str]]:
	#	detail = self.get_detail(uuid)
	#	if detail is None: return None
	#	
	#	ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n'
	#	ticketxml += ''.join(['  <Circle Id="{}" HostedDomain="live.com" />\r\n'.format(circle_id) for circle_id in detail.subscribed_ab_stores if circle_id.startswith('00000000-0000-0000-0009')])
	#	ticketxml += '  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
	#		datetime.utcnow().isoformat()[0:19] + 'Z', cid,
	#	)
	#	# Possible system of signature creation:
	#	# - SHA-1 hash ticket XML (judging from the fact that `CircleTicket` is used in `USR SHA`, and MS seems to have a history of favouring SHA-1)
	#	# - Signatures from samples were 256 bytes long, or 2048 bits long, possibly leading to RSA-2048
	#	# - In that case, sign SHA-1 hash with RSA-2048
	#	return misc.sign_with_new_key_and_b64(ticketxml)
	#
	#def msn_get_circleticket(self, uuid: str) -> Optional[Tuple[str, str]]:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
	#		if dbuser is None: return None
	#		tik = dbuser.get_front_data('msn', 'circleticket')
	#		if tik is None:
	#			from front.msn.misc import cid_format
	#			cid = cid_format(uuid, decimal = True)
	#			tik = self.msn_build_circleticket(uuid, cid)
	#			dbuser.set_front_data('msn', 'circleticket', tik)
	#			sess.add(dbuser)
	#	return tik
	
	def get_oim_batch(self, user: User) -> List[OIM]:
		tmp_oims = []
		
		path = _get_oim_path(user.uuid)
		if path.exists():
			for oim_path in path.iterdir():
				if not oim_path.is_file(): continue
				oim = self.get_oim_single(user, oim_path.name)
				if oim is None: continue
				tmp_oims.append(oim)
		return tmp_oims
	
	def get_oim_single(self, user: User, uuid: str, *, mark_read: bool = False) -> Optional[OIM]:
		oim_path = _get_oim_path(user.uuid) / uuid
		
		if oim_path.is_file():
			return None
		
		json_oim = json.loads(oim_path.read_text())
		if not isinstance(json_oim, dict):
			return None
		
		oim = OIM(
			json_oim['uuid'], json_oim['run_id'], json_oim['from'], json_oim['from_friendly']['friendly_name'], user.email, iso_parser.parse(json_oim['sent']),
			json_oim['message']['text'], json_oim['message']['utf8'],
			headers = json_oim['headers'],
			from_friendly_encoding = json_oim['from_friendly']['encoding'], from_friendly_charset = json_oim['from_friendly']['charset'], from_user_id = json_oim['from_user_id'],
			origin_ip = json_oim['origin_ip'], oim_proxy = json_oim['proxy']
		)
		if mark_read:
			json_oim['is_read'] = True
			oim_path.write_text(json.dumps(json_oim))
		
		return oim
	
	def save_oim(self, bs: 'BackendSession', recipient_uuid: str, run_id: str, origin_ip: str, message: str, utf8: bool, *, from_friendly: Optional[str] = None, from_friendly_charset: str = 'utf-8', from_friendly_encoding: str = 'B', from_user_id: Optional[str] = None, headers: Dict[str, str] = {}, oim_proxy: Optional[str] = None) -> None:
		assert bs is not None
		user = bs.user
		
		path = _get_oim_path(recipient_uuid)
		path.mkdir(exist_ok = True)
		oim_uuid = misc.gen_uuid().upper()
		oim_path = path / oim_uuid
		
		if oim_path.is_file():
			return
		
		oim_json = {} # type: Dict[str, Any]
		oim_json['uuid'] = oim_uuid
		oim_json['run_id'] = run_id
		oim_json['from'] = user.email
		oim_json['from_friendly'] = {
			'friendly_name': from_friendly,
			'encoding': (None if from_friendly is None else from_friendly_encoding),
			'charset': (None if from_friendly is None else from_friendly_charset),
		}
		oim_json['from_user_id'] = from_user_id
		oim_json['is_read'] = False
		oim_json['sent'] = misc.date_format(datetime.utcnow())
		oim_json['origin_ip'] = origin_ip
		oim_json['proxy'] = oim_proxy
		oim_json['headers'] = headers
		oim_json['message'] = {
			'text': message,
			'utf8': utf8,
		}
		
		oim_path.write_text(json.dumps(oim_json))
		
		oim = OIM(
			oim_json['uuid'], oim_json['run_id'], oim_json['from'], oim_json['from_friendly']['friendly_name'], user.email, iso_parser.parse(oim_json['sent']),
			oim_json['message']['text'], oim_json['message']['utf8'],
			headers = oim_json['headers'],
			from_friendly_encoding = oim_json['from_friendly']['encoding'], from_friendly_charset = oim_json['from_friendly']['charset'], from_user_id = oim_json['from_user_id'],
			origin_ip = oim_json['origin_ip'], oim_proxy = oim_json['proxy']
		)
		
		bs.me_contact_notify_oim(recipient_uuid, oim)
	
	def delete_oim(self, recipient_uuid: str, uuid: str) -> None:
		oim_path = _get_oim_path(recipient_uuid) / uuid
		if not oim_path.is_file():
			return
		oim_path.unlink()
	
	#def msn_create_circle(self, uuid: str, circle_name: str, owner_friendly: str, membership_access: int, request_membership_option: int, is_presence_enabled: bool) -> Optional[Tuple[str, str]]:
	#	with Session() as sess:
	#		head = self.get(uuid)
	#		if head is None: return None
	#		
	#		circle_id = '00000000-0000-0000-0009-{}'.format(misc.gen_uuid()[-12:])
	#		dbcirclestore = DBCircleStore(
	#			circle_id = circle_id, circle_name = circle_name,
	#			owner_email = head.email, owner_friendly = owner_friendly, membership_access = membership_access, request_membership_option = request_membership_option, is_presence_enabled = is_presence_enabled,
	#		)
	#		
	#		dbcirclemembership = DBCircleMembership(
	#			circle_id = circle_id, member_email = head.email, member_role = int(ABRelationshipRole.Admin), member_state = int(ABRelationshipState.Accepted),
	#		)
	#		
	#		circleuser_uuid = misc.gen_uuid()
	#		circledbuser = DBUser(
	#			uuid = circleuser_uuid, email = '{}@live.com'.format(circle_id), relay = True, verified = False,
	#			name = circle_name, message = '',
	#			password = hasher.encode(gen_salt(length = 32)), settings = {}, subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000', circle_id],
	#		)
	#		circledbuser.set_front_data('msn', 'circle', True)
	#		
	#		circledbuser_usercontact = DBUserContact(
	#			user_uuid = circleuser_uuid, uuid = head.uuid,
	#			name = head.email, message = '',
	#			lists = (Lst.FL | Lst.AL), groups = {},
	#		)
	#		
	#		circleuser_abstore = DBAddressBook(
	#			member_uuid = circledbuser.uuid, ab_id = '00000000-0000-0000-0000-000000000000',
	#		)
	#		circleuser_abstore.date_last_modified = datetime.utcnow()
	#		
	#		circledbabmetadata = DBABMetadata(
	#			ab_id = circle_id, ab_type = 'Group',
	#		)
	#		circledbaddressbook = DBAddressBook(
	#			member_uuid = circledbuser.uuid, ab_id = circle_id,
	#		)
	#		self_circledbabcontact = DBAddressBookContact(
	#			ab_id = circle_id, contact_uuid = misc.gen_uuid(), contact_member_uuid = head.uuid,
	#			type = 'Circle', email = head.email, name = head.status.name or head.email,
	#			groups = {}, is_messenger_user = True, annotations = {},
	#		)
	#		self_circledbabcontactnetworkinfo = DBAddressBookContactNetworkInfo(
	#			contact_uuid = self_circledbabcontact.contact_uuid, ab_id = circle_id,
	#			domain_id = int(NetworkID.WINDOWS_LIVE), domain_tag = 'WL', source_id = head.email, display_name = head.status.name or head.email,
	#			relationship_type = int(ABRelationshipType.Circle), relationship_role = int(ABRelationshipRole.Admin), relationship_state = int(ABRelationshipState.Accepted), relationship_state_date = datetime.utcnow(),
	#		)
	#		sess.add_all([dbcirclestore, dbcirclemembership, circledbuser,  circledbuser_usercontact, circleuser_abstore, circledbabmetadata, circledbaddressbook, self_circledbabcontact, self_circledbabcontactnetworkinfo])
	#	return circle_id, circleuser_uuid
	#
	#def msn_get_circle_metadata(self, circle_id: str) -> Optional[CircleMetadata]:
	#	with Session() as sess:
	#		dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.circle_id == circle_id).one_or_none()
	#		if dbcirclestore is None: return None
	#		
	#		return CircleMetadata(
	#			dbcirclestore.circle_id, dbcirclestore.owner_email, dbcirclestore.owner_friendly, dbcirclestore.circle_name, dbcirclestore.date_last_modified,
	#			dbcirclestore.membership_access, dbcirclestore.request_membership_option, dbcirclestore.is_presence_enabled,
	#		)
	#
	#def msn_circle_set_user_membership(self, circle_id: str, email: str, *, member_role: Optional[ABRelationshipRole] = None, member_state: Optional[ABRelationshipState] = None) -> bool:
	#	with Session() as sess:
	#		dbcirclemembership = sess.query(DBCircleMembership).filter(DBCircleMembership.circle_id == circle_id, DBCircleMembership.member_email == email).one_or_none()
	#		
	#		if dbcirclemembership is None:
	#			if member_role is not None and member_state is not None:
	#				dbcirclemembership = DBCircleMembership(
	#					circle_id = circle_id, member_email = email, member_role = int(member_role), member_state = int(member_state),
	#				)
	#			else:
	#				return False
	#		else:
	#			if member_role is not None:
	#				dbcirclemembership.member_role = int(member_role)
	#			if member_state is not None:
	#				dbcirclemembership.member_state = int(member_state)
	#		sess.add(dbcirclemembership)
	#	return True
	#
	#def msn_get_circle_membership(self, circle_id: str, email: str) -> Optional[CircleMembership]:
	#	with Session() as sess:
	#		dbcirclemembership = sess.query(DBCircleMembership).filter(DBCircleMembership.circle_id == circle_id, DBCircleMembership.member_email == email).one_or_none()
	#		if dbcirclemembership is None: return None
	#		
	#		return CircleMembership(
	#			circle_id, email, ABRelationshipRole(dbcirclemembership.member_role), ABRelationshipState(dbcirclemembership.member_state),
	#		)
	
	def save_batch(self, to_save: List[Tuple[User, UserDetail]]) -> None:
		with Session() as sess:
			for user, detail in to_save:
				dbusercontacts_to_add = []
				dbusergroups_to_add = []
				
				dbuser = sess.query(DBUser).filter(DBUser.uuid == user.uuid).one()
				dbuser.name = user.status.name
				dbuser.message = _get_persisted_status_message(user.status)
				dbuser.settings = user.settings
				sess.add(dbuser)
				
				dbusergroups = sess.query(DBUserGroup).filter(DBUserGroup.user_uuid == user.uuid)
				for tmp in dbusergroups:
					if tmp.group_id not in detail._groups_by_id:
						sess.delete(tmp)
				for g in detail._groups_by_id.values():
					dbusergroup = sess.query(DBUserGroup).filter(DBUserGroup.user_uuid == user.uuid, DBUserGroup.group_id == g.id, DBUserGroup.group_uuid == g.uuid).one_or_none()
					if dbusergroup is None:
						dbusergroup = DBUserGroup(
							user_uuid = user.uuid, group_id = g.id, group_uuid = g.uuid,
							name = g.name, is_favorite = g.is_favorite,
						)
					else:
						dbusergroup.name = g.name
						dbusergroup.is_favorite = g.is_favorite
						dbusergroup.date_last_modified = datetime.utcnow()
					g.date_last_modified = dbusergroup.date_last_modified
					dbusergroups_to_add.append(dbusergroup)
				if dbusergroups_to_add:
					sess.add_all(dbusergroups_to_add)
				
				dbusercontacts = sess.query(DBUserContact).filter(DBUserContact.user_uuid == user.uuid)
				for tmp in dbusercontacts:
					if tmp.uuid not in detail.contacts:
						sess.delete(tmp)
				for c in detail.contacts.values():
					dbusercontact = sess.query(DBUserContact).filter(DBUserContact.user_uuid == user.uuid, DBUserContact.uuid == c.head.uuid).one_or_none()
					status_message = _get_persisted_status_message(c.status)
					if dbusercontact is None:
						dbusercontact = DBUserContact(
							user_uuid = user.uuid, uuid = c.head.uuid,
							name = c.status.name, message = status_message,
							lists = c.lists, groups = [{
								'id': group.id, 'uuid': group.uuid,
							} for group in c._groups.copy()],
						)
					else:
						dbusercontact.name = c.status.name
						dbusercontact.message = status_message
						dbusercontact.lists = c.lists
						dbusercontact.groups = [{
							'id': group.id, 'uuid': group.uuid,
						} for group in c._groups.copy()]
					dbusercontacts_to_add.append(dbusercontact)
				if dbusercontacts_to_add:
					sess.add_all(dbusercontacts_to_add)

def _get_persisted_status_message(status: UserStatus) -> str:
	if not status._persistent:
		return ''
	return status.message

def _get_oim_path(recipient_uuid: str) -> Path:
	return Path('storage/oim') / recipient_uuid
