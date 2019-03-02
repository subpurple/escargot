from typing import Dict, Optional, List, Tuple, Set, Any
from datetime import datetime
from urllib.parse import quote
import asyncio, traceback

from util.hash import hasher, hasher_md5, hasher_md5crypt, gen_salt
from util import misc

from . import error
from .db import Session, User as DBUser, UserGroup as DBUserGroup, UserContact as DBUserContact, ABStore as DBABStore, ABStoreContact as DBABStoreContact, ABStoreContactNetworkInfo as DBABStoreContactNetworkInfo, ABMetadata as DBABMetadata, OIM as DBOIM, YahooOIM as DBYahooOIM
from .models import User, Contact, ContactGroupEntry, ABContact, ABRelationshipRole, ABRelationshipState, ABRelationshipType, NetworkInfo, RelationshipInfo, UserStatus, UserDetail, NetworkID, Lst, Group, OIMMetadata, YahooOIM, MessageData

class UserService:
	loop: asyncio.AbstractEventLoop
	_cache_by_uuid: Dict[str, Optional[User]]
	_worklist_sync_ab: Dict[int, Tuple[str, User, Dict[str, Any]]]
	_working_ab_sync_ids: List[int]
	
	def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
		self.loop = loop
		self._cache_by_uuid = {}
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
			detail = UserDetail(set(dbuser.subscribed_ab_stores))
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
				ab_id, user, fields = self._worklist_sync_ab.pop(key)
				if not ab_id: continue
				self._working_ab_sync_ids.append(key)
				batch.append((key,ab_id,user,fields))
			self.save_batch_ab(batch)
		except:
			traceback.print_exc()
	
	def check_ab(self, ab_id: str, *, uuid: Optional[str] = None) -> bool:
		with Session() as sess:
			return self._get_ab_store(ab_id, uuid = uuid) is not None
	
	def create_ab(self, ab_id: str, type: str, user: User) -> None:
		with Session() as sess:
			dbabmetadata = sess.query(DBABMetadata).filter(DBABMetadata.ab_id == ab_id).one_or_none()
			if not dbabmetadata:
				dbabmetadata = DBABMetadata(
					ab_id = ab_id, ab_type = type,
				)
				sess.add(dbabmetadata)
			
			if dbabmetadata.ab_type == 'Individual':
				dbabstore = sess.query(DBABStore).filter(DBABStore.member_uuid == user.uuid, DBABStore.ab_id == ab_id).one_or_none()
			elif dbabmetadata.ab_type == 'Group':
				dbabstore = sess.query(DBABStore).filter(DBABStore.ab_id == ab_id).one_or_none()
			
			if not dbabstore:
				dbabstore = DBABStore(
					member_uuid = user.uuid, ab_id = ab_id,
				)
				sess.add(dbabstore)
	
	def mark_ab_modified(self, ab_id: str, fields: Dict[str, Any], user: User) -> int:
		id = len(self._worklist_sync_ab.keys())
		self._worklist_sync_ab[id] = (ab_id, user, fields)
		return id
	
	async def mark_ab_modified_async(self, ab_id: str, fields: Dict[str, Any], user: User) -> None:
		id = self.mark_ab_modified(ab_id, fields, user)
		await asyncio.sleep(1)
		while id in self._working_ab_sync_ids:
			await asyncio.sleep(0.1)
	
	def ab_get_entry_by_uuid(self, ab_id: str, ctc_uuid: str, user: User) -> Optional[ABContact]:
		with Session() as sess:
			tpl = self._get_ab_store(ab_id, uuid = user.uuid)
			if tpl is None:
				return None
			ab_type, dbabstore = tpl
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == ctc_uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			
			if dbabstorecontact is None:
				return None
			
			return self._ab_get_entry(ab_type, dbabstorecontact)
	
	def ab_get_entry_by_email(self, ab_id: str, email: str, ctc_type: str, user: User) -> Optional[ABContact]:
		with Session() as sess:
			tpl = self._get_ab_store(ab_id, uuid = user.uuid)
			if tpl is None:
				return None
			ab_type, dbabstore = tpl
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.email == email, DBABStoreContact.type == ctc_type, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			
			if dbabstorecontact is None:
				for ab_id, user_other, fields in self._worklist_sync_ab.values():
					if ab_id == ab_id and user_other is user:
						for c in fields['contacts']:
							if c.email == email and c.type == ctc_type:
								return c
				return None
			
			return self._ab_get_entry(ab_type, dbabstorecontact)
	
	def _ab_get_entry(self, ab_type: str, dbabstorecontact: DBABStoreContact) -> Optional[ABContact]:
		head = None
		
		with Session() as sess:
			if dbabstorecontact.contact_member_uuid is not None:
				head = self.get(dbabstorecontact.contact_member_uuid)
				if head is None: return None
			
			annotations = {} # type: Dict[Any, Any]
			for annots in dbabstorecontact.annotations:
				annotations.update(annots)
			dbabstorecontactnetworkinfos = sess.query(DBABStoreContactNetworkInfo).filter(DBABStoreContactNetworkInfo.contact_uuid == dbabstorecontact.contact_uuid, DBABStoreContactNetworkInfo.ab_id == dbabstorecontact.ab_id, DBABStoreContactNetworkInfo.ab_owner_uuid == (dbabstorecontact.ab_owner_uuid if ab_type == 'Individual' else None))
			networkinfos = {
				NetworkID(dbabstorecontactnetworkinfo.domain_id): NetworkInfo(
					NetworkID(dbabstorecontactnetworkinfo.domain_id), dbabstorecontactnetworkinfo.source_id, dbabstorecontactnetworkinfo.domain_tag,
					dbabstorecontactnetworkinfo.display_name, RelationshipInfo(
						ABRelationshipType(dbabstorecontactnetworkinfo.relationship_type), ABRelationshipRole(dbabstorecontactnetworkinfo.relationship_role), ABRelationshipState(dbabstorecontactnetworkinfo.relationship_state), relationship_state_date = dbabstorecontactnetworkinfo.relationship_state_date,
					),
					invite_message = dbabstorecontactnetworkinfo.invite_message, date_created = dbabstorecontactnetworkinfo.date_created, date_last_modified = dbabstorecontactnetworkinfo.date_last_modified,
				) for dbabstorecontactnetworkinfo in dbabstorecontactnetworkinfos}
			return ABContact(
				dbabstorecontact.type, dbabstorecontact.contact_uuid, dbabstorecontact.email, dbabstorecontact.name, set(dbabstorecontact.groups),
				networkinfos = networkinfos, member_uuid = dbabstorecontact.contact_member_uuid, is_messenger_user = dbabstorecontact.is_messenger_user, annotations = annotations, date_last_modified = dbabstorecontact.date_last_modified,
			)
	
	def get_ab_contents(self, ab_id: str, user: User) -> Optional[Tuple[str, User, datetime, datetime, Dict[str, ABContact]]]:
		with Session() as sess:
			tpl = self._get_ab_store(ab_id, uuid = user.uuid)
			if tpl is None:
				return None
			ab_type, dbabstore = tpl
			
			head = self.get(dbabstore.member_uuid)
			if head is None: return None
			
			contacts = {}
			
			dbabstorecontacts = sess.query(DBABStoreContact).filter(DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None))
			for dbabstorecontact in dbabstorecontacts:
				ctc = self._ab_get_entry(ab_type, dbabstorecontact)
				if ctc is None: continue
				contacts[dbabstorecontact.contact_uuid] = ctc
			return ab_type, head, dbabstore.date_created, dbabstore.date_last_modified, contacts
	
	def ab_delete_entry(self, ab_id: str, ctc_uuid: str, user: User) -> None:
		with Session() as sess:
			tpl = self._get_ab_store(ab_id, uuid = user.uuid)
			if tpl is None:
				return None
			ab_type, dbabstore = tpl
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == ctc_uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			if dbabstorecontact is not None:
				sess.delete(dbabstorecontact)
				
				dbabstore.date_last_modified = datetime.utcnow()
				sess.add(dbabstore)
	
	def ab_delete_entry_by_email(self, ab_id: str, email: str, ctc_type: str, user: User) -> None:
		with Session() as sess:
			tpl = self._get_ab_store(ab_id, uuid = user.uuid)
			if tpl is None:
				return None
			ab_type, dbabstore = tpl
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.email == email, DBABStoreContact.type == ctc_type, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			if dbabstorecontact is not None:
				sess.delete(dbabstorecontact)
				
				dbabstore.date_last_modified = datetime.utcnow()
				sess.add(dbabstore)
	
	def save_batch_ab(self, batch: List[Tuple[int, str, User, Dict[str, Any]]]) -> None:
		with Session() as sess:
			for id, ab_id, user, fields in batch:
				updated = False
				tpl = self._get_ab_store(ab_id, uuid = user.uuid)
				if tpl is None:
					return None
				ab_type, dbabstore = tpl
				
				if 'contacts' in fields:
					for c in fields['contacts']:
						dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == c.uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
						if dbabstorecontact is None:
							dbabstorecontact = DBABStoreContact(
								ab_id = ab_id, ab_owner_uuid = (user.uuid if ab_type == 'Individual' else None),
								contact_uuid = c.uuid, contact_member_uuid = c.member_uuid, type = c.type, email = c.email, name = c.name, groups = list(c.groups), is_messenger_user = c.is_messenger_user, annotations = [{
									name: value
								} for name, value in c.annotations.items()],
							)
						else:
							dbabstorecontact.email = c.email
							dbabstorecontact.name = c.name
							dbabstorecontact.groups = list(c.groups)
							dbabstorecontact.is_messenger_user = c.is_messenger_user
							dbabstorecontact.annotations = [{
								name: value
							} for name, value in c.annotations.items()]
						dbabstorecontact.date_last_modified = datetime.utcnow()
						c.date_last_modified = dbabstorecontact.date_last_modified
						sess.add(dbabstorecontact)
						
						for networkinfo in c.networkinfos.values():
							dbabstorecontactnetworkinfo = sess.query(DBABStoreContactNetworkInfo).filter(DBABStoreContactNetworkInfo.contact_uuid == c.uuid, DBABStoreContactNetworkInfo.ab_id == ab_id, DBABStoreContactNetworkInfo.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None), DBABStoreContactNetworkInfo.domain_id == int(networkinfo.domain_id)).one_or_none()
							if dbabstorecontactnetworkinfo is None:
								dbabstorecontactnetworkinfo = DBABStoreContactNetworkInfo(
									contact_uuid = c.uuid, ab_id = ab_id, ab_owner_uuid = (user.uuid if ab_type == 'Individual' else None),
									domain_id = int(networkinfo.domain_id), source_id = networkinfo.source_id, domain_tag = networkinfo.domain_tag, display_name = networkinfo.display_name,
									relationship_type = int(networkinfo.relationship_info.relationship_type), relationship_role = int(networkinfo.relationship_info.relationship_role), relationship_state = int(networkinfo.relationship_info.relationship_state),
								)
								dbabstorecontactnetworkinfo.relationship_state_date = datetime.utcnow()
							else:
								dbabstorecontactnetworkinfo.domain_tag = networkinfo.domain_tag
								dbabstorecontactnetworkinfo.display_name = networkinfo.display_name
								dbabstorecontactnetworkinfo.relationship_type = int(networkinfo.relationship_info.relationship_type)
								dbabstorecontactnetworkinfo.relationship_role = int(networkinfo.relationship_info.relationship_role)
								dbabstorecontactnetworkinfo.relationship_state = int(networkinfo.relationship_info.relationship_state)
								dbabstorecontactnetworkinfo.relationship_state_date = datetime.utcnow()
								dbabstorecontactnetworkinfo.invite_message = networkinfo.invite_message
							dbabstorecontactnetworkinfo.date_last_modified = datetime.utcnow()
							networkinfo.date_last_modified = dbabstorecontactnetworkinfo.date_last_modified
							sess.add(dbabstorecontactnetworkinfo)
					updated = True
				
				if updated:
					dbabstore.date_last_modified = datetime.utcnow()
					sess.add(dbabstore)
				self._working_ab_sync_ids.remove(id)
	
	def _get_ab_store(self, ab_id: str, *, uuid: Optional[str] = None) -> Optional[Tuple[str, DBABStore]]:
		with Session() as sess:
			dbabmetadata = sess.query(DBABMetadata).filter(DBABMetadata.ab_id == ab_id).one_or_none()
			
			if dbabmetadata is None:
				return None
			
			if dbabmetadata.ab_type == 'Individual':
				if not uuid:
					return None
				
				dbabstore = sess.query(DBABStore).filter(DBABStore.member_uuid == uuid, DBABStore.ab_id == ab_id).one_or_none()
			elif dbabmetadata.ab_type == 'Group':
				dbabstore = sess.query(DBABStore).filter(DBABStore.ab_id == ab_id).one_or_none()
		
		return dbabmetadata.ab_type, dbabstore
	
	def set_ab_subscription(self, uuid: str, ab_id: str) -> None:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			
			if ab_id in dbuser.subscribed_ab_stores: return None
			subscribed_ab_stores = set(dbuser.subscribed_ab_stores)
			subscribed_ab_stores.add(ab_id)
			dbuser.subscribed_ab_stores = list(subscribed_ab_stores)
			sess.add(dbuser)
	
	#def msn_update_circleticket(self, uuid: str, cid: str) -> None:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
	#		if dbuser is not None:
	#			ticket, ticket_sig = self.msn_build_circleticket(uuid, cid)
	#			dbuser.set_front_data('msn', 'circleticket', [ticket, ticket_sig])
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
	#	return *misc.sign_with_new_key_and_b64(ticketxml)
	#
	#def msn_get_circleticket(self, uuid: str) -> Optional[List[str]]:
	#	with Session() as sess:
	#		dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
	#		if dbuser is None: return None
	#		return dbuser.get_front_data('msn', 'circleticket')
	
	def msn_get_oim_batch(self, to_member_name: str) -> List[OIMMetadata]:
		with Session() as sess:
			query = sess.query(DBOIM).filter(DBOIM.to_member_name == to_member_name, DBOIM.is_read == False)
			tmp_oims = [
				OIMMetadata(
					oim.run_id, oim.oim_num, oim.from_member_name, oim.from_member_friendly,
					oim.to_member_name, oim.oim_sent, len(oim.content),
				)
				for oim in query
			]
		return tmp_oims
	
	def msn_get_oim_single(self, to_member_name: str, run_id: str) -> List[OIMMetadata]:
		with Session() as sess:
			dboim = sess.query(DBOIM).filter(DBOIM.to_member_name == to_member_name, DBOIM.run_id == run_id).one_or_none()
			if dboim is None: return []
			return [OIMMetadata(
				dboim.run_id, dboim.oim_num, dboim.from_member_name, dboim.from_member_friendly,
				dboim.to_member_name, dboim.oim_sent, len(dboim.content),
			)]
	
	def msn_get_oim_message_by_uuid(self, to_member_name: str, run_id: str, markAsRead: bool) -> Optional[str]:
		with Session() as sess:
			dboim = sess.query(DBOIM).filter(DBOIM.to_member_name == to_member_name, DBOIM.run_id == run_id).one_or_none()
			if dboim is None: return None
			msg_content = dboim.content
			if markAsRead:
				dboim.is_read = True
				sess.add(dboim)
		return msg_content
	
	def msn_save_oim(self, run_id: str, seq_num: int, content: str, from_member: str, from_member_friendly: str, recipient: str, sent: datetime) -> None:
		with Session() as sess:
			dboim = sess.query(DBOIM).filter(DBOIM.run_id == run_id).one_or_none()
			if dboim is None:
				dboim = DBOIM(run_id = run_id, from_member_name = from_member, to_member_name = recipient)
			dboim.oim_num = seq_num
			dboim.from_member_friendly = from_member_friendly
			dboim.oim_sent = sent
			dboim.content = content
			dboim.is_read = False
			sess.add(dboim)
	
	def msn_delete_oim(self, run_id: str) -> bool:
		with Session() as sess:
			dboim = sess.query(DBOIM).filter(DBOIM.run_id == run_id).one_or_none()
			if dboim is None: return False
			sess.delete(dboim)
		return True
	
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
	#		circleuser_abstore = DBABStore(
	#			member_uuid = circledbuser.uuid, ab_id = '00000000-0000-0000-0000-000000000000',
	#		)
	#		circleuser_abstore.date_last_modified = datetime.utcnow()
	#		
	#		circledbabmetadata = DBABMetadata(
	#			ab_id = circle_id, ab_type = 'Group',
	#		)
	#		circledbabstore = DBABStore(
	#			member_uuid = circledbuser.uuid, ab_id = circle_id,
	#		)
	#		self_circledbabcontact = DBABStoreContact(
	#			ab_id = circle_id, contact_uuid = misc.gen_uuid(), contact_member_uuid = head.uuid,
	#			type = 'Circle', email = head.email, name = head.status.name or head.email,
	#			groups = {}, is_messenger_user = True, annotations = {},
	#		)
	#		self_circledbabcontactnetworkinfo = DBABStoreContactNetworkInfo(
	#			contact_uuid = self_circledbabcontact.contact_uuid, ab_id = circle_id,
	#			domain_id = int(NetworkID.WINDOWS_LIVE), domain_tag = 'WL', source_id = head.email, display_name = head.status.name or head.email,
	#			relationship_type = int(ABRelationshipType.Circle), relationship_role = int(ABRelationshipRole.Admin), relationship_state = int(ABRelationshipState.Accepted), relationship_state_date = datetime.utcnow(),
	#		)
	#		sess.add_all([dbcirclestore, dbcirclemembership, circledbuser,  circledbuser_usercontact, circleuser_abstore, circledbabmetadata, circledbabstore, self_circledbabcontact, self_circledbabcontactnetworkinfo])
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
	
	def yahoo_get_oim_message_by_recipient(self, recipient_id: str) -> List[YahooOIM]:
		with Session() as sess:
			query = sess.query(DBYahooOIM).filter(DBYahooOIM.recipient_id_primary == recipient_id)
			tmp_oims = []
			for oim in query:
				tmp_oims.append(
					YahooOIM(
						oim.from_id, oim.recipient_id, oim.sent, oim.message, oim.utf8_kv,
					)
				)
				sess.delete(oim)
		return tmp_oims
	
	def yahoo_save_oim(self, message: str, utf8_kv: Optional[bool], from_id: str, recipient_id: str, recipient_id_primary: str, sent: datetime) -> None:
		with Session() as sess:
			dbyahoooim = DBYahooOIM(
				from_id = from_id, recipient_id = recipient_id, recipient_id_primary = recipient_id_primary, sent = sent,
				message = message, utf8_kv = utf8_kv,
			)
			sess.add(dbyahoooim)
	
	def save_batch(self, to_save: List[Tuple[User, UserDetail]]) -> None:
		with Session() as sess:
			for user, detail in to_save:
				dbusercontacts_to_add = []
				dbusergroups_to_add = []
				
				dbuser = sess.query(DBUser).filter(DBUser.uuid == user.uuid).one()
				dbuser.name = user.status.name
				dbuser.message = _get_persisted_status_message(user.status)
				dbuser.settings = user.settings
				dbuser.subscribed_ab_stores = list(detail.subscribed_ab_stores)
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
