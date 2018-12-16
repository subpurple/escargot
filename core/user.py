from typing import Dict, Optional, List, Tuple, Set, Any
from datetime import datetime
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import base64
import asyncio, traceback

from util.hash import hasher, hasher_md5, hasher_md5crypt, gen_salt
from util import misc

from . import error
from .db import Session, User as DBUser, ABStore as DBABStore, ABStoreContact as DBABStoreContact, ABStoreContactNetworkInfo as DBABStoreContactNetworkInfo, ABStoreGroup as DBABStoreGroup, ABMetadata as DBABMetadata, CircleStore as DBCircleStore, OIM as DBOIM, YahooOIM as DBYahooOIM, YahooAlias as DBYahooAlias
from .models import User, Contact, ABContact, NetworkInfo, RelationshipInfo, UserStatus, UserDetail, NetworkID, ABRelationshipType, ABRelationshipRole, ABRelationshipState, Lst, Group, ABGroup, CircleMetadata, OIMMetadata, YahooOIM, YahooAlias, MessageData

class UserService:
	loop: asyncio.AbstractEventLoop
	_cache_by_uuid: Dict[str, Optional[User]]
	_worklist_sync_ab: Dict[int, Tuple[str, User, Dict[str, Any]]]
	
	def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
		self.loop = loop
		self._cache_by_uuid = {}
		self._worklist_sync_ab = {}
		
		loop.create_task(self._worker_sync_ab())
	
	def login(self, email: str, networkid: NetworkID, pwd: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == networkid).one_or_none()
			if dbuser is None:
				dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
				if dbuser is None: return None
			if not hasher.verify(pwd, dbuser.password): return None
			return dbuser.uuid
	
	def msn_login_md5(self, email: str, md5_hash: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.WINDOWS_LIVE).one_or_none()
			if dbuser is None:
				dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
				if dbuser is None: return None
			if not hasher_md5.verify_hash(md5_hash, dbuser.get_front_data('msn', 'pw_md5') or ''): return None
			return dbuser.uuid
	
	def msn_get_md5_salt(self, email: str) -> Optional[str]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.WINDOWS_LIVE).one_or_none()
			if dbuser is None:
				dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
				if dbuser is None: return None
			pw_md5 = dbuser.get_front_data('msn', 'pw_md5')
		if pw_md5 is None: return None
		return hasher.extract_salt(pw_md5)
	
	def yahoo_get_md5_password(self, uuid: str) -> Optional[bytes]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid, DBUser.networkid == NetworkID.YAHOO).one_or_none()
			if dbuser is None:
				dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
				if dbuser is None: return None
			return hasher_md5.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5_unsalted') or '')
	
	def yahoo_get_md5crypt_password(self, uuid: str) -> Optional[bytes]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid, DBUser.networkid == NetworkID.YAHOO).one_or_none()
			if dbuser is None:
				dbuser = sess.query(DBUser).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
				if dbuser is None: return None
			return hasher_md5crypt.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5crypt') or '')
	
	def update_date_login(self, uuid: str) -> None:
		with Session() as sess:
			sess.query(DBUser).filter(DBUser.uuid == uuid).update({
				'date_login': datetime.utcnow(),
			})
	
	def is_user_relay(self, uuid: str) -> Optional[bool]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return dbuser.relay
	
	def get_uuid(self, email: str, networkid: NetworkID) -> Optional[str]:
		with Session() as sess:
			tmp = sess.query(DBUser.uuid).filter(DBUser.email == email, DBUser.networkid == networkid).one_or_none()
			if tmp is None:
				tmp = sess.query(DBUser.uuid).filter(DBUser.email == email, DBUser.networkid == NetworkID.ANY).one_or_none()
			return tmp and tmp[0]
	
	def get(self, uuid: str) -> Optional[User]:
		if uuid is None: return None
		if uuid not in self._cache_by_uuid:
			self._cache_by_uuid[uuid] = self._get_uncached(uuid)
		return self._cache_by_uuid[uuid]
	
	def _get_uncached(self, uuid: str) -> Optional[User]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			status = UserStatus(dbuser.name, dbuser.message)
			return User(dbuser.uuid, dbuser.email, NetworkID(dbuser.networkid), dbuser.verified, status, dbuser.settings, dbuser.date_created)
	
	def get_detail(self, uuid: str) -> Optional[UserDetail]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			detail = UserDetail(set(dbuser.subscribed_ab_stores))
			for g in dbuser.groups:
				grp = Group(**g)
				detail.groups[grp.id] = grp
			for c in dbuser.contacts:
				ctc_head = self.get(c['uuid'])
				if ctc_head is None: continue
				status = UserStatus(c['name'], c['message'])
				ctc = Contact(
					ctc_head, set(c['groups']), c['lists'], status,
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
				ab_id, user, fields = self._worklist_sync_ab.pop(key, None)
				if not ab_id: continue
				batch.append((ab_id,user,fields))
			self.save_batch_ab(batch)
		except:
			traceback.print_exc()
	
	def check_ab(self, ab_id: str, *, uuid: Optional[str] = None) -> bool:
		with Session() as sess:
			_, dbabstore = self._get_ab_store(ab_id, uuid = uuid)
			
			if dbabstore is None:
				return False
			
			return True
	
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
	
	def mark_ab_modified(self, ab_id: str, fields: Dict[str, Any], user: User) -> None:
		id = len(list(self._worklist_sync_ab.keys()))
		# TODO: Block function when writing to database so that new changes can be retreived by other parts of the server.
		self._worklist_sync_ab[id] = (ab_id, user, fields)
	
	def delete_ab_group(self, ab_id: str, group_id: str, user: User) -> None:
		with Session() as sess:
			ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
			
			if dbabstore is None:
				return None
			
			dbabstoregroup = sess.query(DBABStoreGroup).filter(DBABStoreGroup.group_id == group_id, DBABStoreGroup.ab_id == ab_id, DBABStoreGroup.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None))
			
			if dbabstoregroup is None:
				return None
			
			sess.delete(dbabstoregroup)
			
			dbabstorecontacts = sess.query(DBABStoreContact).filter(DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None))
			for dbabstorecontact in dbabstorecontacts:
				dbabstorecontact.groups.remove(group_id)
			sess.add_all(dbabstorecontacts)
			
			sess.add(dbabstore)
	
	def ab_get_entry_by_uuid(self, ab_id: str, ctc_uuid: str, user: User) -> Optional[ABContact]:
		with Session() as sess:
			ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == ctc_uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			
			if dbabstorecontact is None:
				return None
			
			return self._ab_get_entry(ab_type, dbabstorecontact)
	
	def _ab_get_entry(self, ab_type: str, dbabstorecontact: DBABStoreContact) -> Optional[ABContact]:
		with Session() as sess:
			head = self.get(dbabstorecontact.contact_uuid)
			if head is None: return None
			
			annotations = {}
			for annotation in dbabstorecontact.annotations:
				annotations.update(annotation)
			dbabstorecontactnetworkinfos = sess.query(DBABStoreContactNetworkInfo).filter(DBABStoreContactNetworkInfo.contact_uuid == dbabstorecontact.contact_uuid, DBABStoreContactNetworkInfo.ab_id == dbabstorecontact.ab_id, DBABStoreContactNetworkInfo.ab_owner_uuid == (dbabstorecontact.ab_owner_uuid if ab_type == 'Individual' else None))
			networkinfos = {
				NetworkID(dbabstorecontactnetworkinfo.domain_id): NetworkInfo(
					NetworkID(dbabstorecontactnetworkinfo.domain_id), dbabstorecontactnetworkinfo.source_id, dbabstorecontactnetworkinfo.domain_tag,
					dbabstorecontactnetworkinfo.display_name, RelationshipInfo(
						ABRelationshipType(dbabstorecontactnetworkinfo.relationship_type), ABRelationshipRole(dbabstorecontactnetworkinfo.relationship_role), ABRelationshipState(dbabstorecontactnetworkinfo.relationship_state), dbabstorecontactnetworkinfo.relationship_state_date,
					),
					invite_message = dbabstorecontactnetworkinfo.invite_message, date_created = dbabstorecontactnetworkinfo.date_created, date_last_modified = dbabstorecontactnetworkinfo.date_last_modified,
				) for dbabstorecontactnetworkinfo in dbabstorecontactnetworkinfos}
			return ABContact(
				dbabstorecontact.type, dbabstorecontact.contact_uuid, dbabstorecontact.email, dbabstorecontact.name, set(dbabstorecontact.groups), networkinfos,
				is_messenger_user = dbabstorecontact.is_messenger_user, annotations = annotations, date_last_modified = dbabstorecontact.date_last_modified,
			)
	
	def ab_get_group_by_id(self, ab_id, group_id: str, user: User) -> Optional[ABGroup]:
		with Session() as sess:
			ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
			
			dbabstorecontact = sess.query(DBABStoreGroup).filter(DBABStoreGroup.group_id == group_id, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			
			if dbabstorecontact is None:
				return None
			
			return ABGroup(dbabstoregroup.group_id, dbabstoregroup.name, dbabstoregroup.is_favorite, date_last_modified = dbabstoregroup.date_last_modified)
	
	def get_ab_contents(self, ab_id: str, user: User) -> Optional[Tuple[str, datetime, datetime, Dict[str, Group], Dict[str, Contact]]]:
		with Session() as sess:
			ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
			
			if dbabstore is None:
				return None
			
			groups = {}
			contacts = {}
			
			dbabstoregroups = sess.query(DBABStoreGroup).filter(DBABStoreGroup.ab_id == ab_id, DBABStoreGroup.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None))
			for dbabstoregroup in dbabstoregroups:
				grp = ABGroup(dbabstoregroup.group_id, dbabstoregroup.name, dbabstoregroup.is_favorite, date_last_modified = dbabstoregroup.date_last_modified)
				if grp is None: continue
				groups[id] = grp
			
			dbabstorecontacts = sess.query(DBABStoreContact).filter(DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None))
			for dbabstorecontact in dbabstorecontacts:
				ctc = self._ab_get_entry(ab_type, dbabstorecontact)
				if ctc is None: continue
				contacts[dbabstorecontact.contact_uuid] = ctc
			return ab_type, dbabstore.date_created, dbabstore.date_last_modified, groups, contacts
	
	def ab_delete_entry(self, ab_id: str, ctc_uuid: str, user: User) -> None:
		with Session() as sess:
			ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
			
			if dbabstore is None:
				return None
			
			dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == ctc_uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
			if dbabstorecontact is not None:
				sess.delete(dbabstorecontact)
			
			sess.add(dbabstore)
	
	def save_batch_ab(self, batch: Tuple[str, User, Dict[str, Any]]) -> None:
		with Session() as sess:
			for ab_id, user, fields in batch:
				updated = False
				ab_type, dbabstore = self._get_ab_store(ab_id, uuid = user.uuid)
				
				if dbabstore is None:
					return None
				
				if 'contacts' in fields:
					for c in fields['contacts']:
						dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == c.uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
						if dbabstorecontact is None:
							dbabstorecontact = DBABStoreContact(
								ab_id = ab_id, ab_owner_uuid = (user.uuid if ab_type == 'Individual' else None),
								contact_uuid = c.uuid, type = c.type, email = c.email, name = c.name, groups = list(c.groups), is_messenger_user = c.is_messenger_user, annotations = [{
									name: value
								} for name, value in c.annotations.items()],
							)
						else:
							dbabstorecontact = sess.query(DBABStoreContact).filter(DBABStoreContact.contact_uuid == c.uuid, DBABStoreContact.ab_id == ab_id, DBABStoreContact.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
							if dbabstorecontact is None: continue
							dbabstorecontact.type = c.type
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
								dbabstorecontactnetworkinfo.invite_message = invite_message
							dbabstorecontactnetworkinfo.date_last_modified = datetime.utcnow()
							networkinfo.date_last_modified = dbabstorecontactnetworkinfo.date_last_modified
							sess.add(dbabstorecontactnetworkinfo)
					updated = True
				
				if 'groups' in fields:
					for g in fields['groups']:
						dbabstoregroup = sess.query(DBABStoreGroup).filter(DBABStoreGroup.group_id == g.id, DBABStoreGroup.ab_id == ab_id, DBABStoreGroup.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
						if dbabstoregroup is None:
							dbabstoregroup = DBABStoreGroup(
								ab_id = ab_id, ab_owner_uuid = user.uuid, group_id = g.id,
								name = g.name,
							)
						else:
							dbabstoregroup = sess.query(DBABStoreGroup).filter(DBABStoreGroup.group_id == g.id, DBABStoreGroup.ab_id == ab_id, DBABStoreGroup.ab_owner_uuid == (user.uuid if ab_type == 'Individual' else None)).one_or_none()
							if dbabstoregroup is None: continue
							dbabstoregroup.name = g.name
							dbabstoregroup.date_last_modified = datetime.utcnow()
						g.date_last_modified = dbabstoregroup.date_last_modified
						sess.add(dbabstoregroup)
					updated = True
				
				if updated: dbabstore.date_last_modified = datetime.utcnow()
				sess.add(dbabstore)
	
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
			dbuser.subscribed_ab_stores.append(ab_id)
			sess.add(dbuser)
	
	def msn_update_circleticket(self, uuid: str, cid: str) -> None:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is not None:
				ticket, ticket_sig = self.msn_build_circleticket(uuid, cid)
				dbuser.set_front_data('msn', 'circleticket', [ticket, ticket_sig])
				sess.add(dbuser)
	
	def msn_build_circleticket(self, uuid: str, cid: str) -> Optional[Tuple[str, str]]:
		detail = self.get_detail(uuid)
		if detail is None: return None
		
		ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n'
		ticketxml += ''.join(['  <Circle Id="{}" HostedDomain="live.com" />\r\n'.format(circle_id) for circle_id in detail.contacts.keys() if circle_id.startswith('00000000-0000-0000-0009')])
		ticketxml += '  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
			datetime.utcnow().isoformat()[0:19] + 'Z', cid,
		)
		ticketxml = ticketxml.encode('utf-8')
		# Possible system of signature creation:
		# - SHA-1 hash ticket XML (judging from the fact that `CircleTicket` is used in `USR SHA`, and MS seems to have a history of favouring SHA-1)
		# - Signatures from samples were 256 bytes long, or 2048 bits long, possibly leading to RSA-2048
		# - In that case, sign SHA-1 hash with RSA-2048
		ticketxml_sig = pkcs1_15.new(RSA.generate(2048)).sign(SHA1.new(ticketxml))
		return base64.b64encode(ticketxml).decode('ascii'), base64.b64encode(ticketxml_sig).decode('ascii')
	
	def msn_get_circleticket(self, uuid: str) -> Optional[List[str]]:
		with Session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return dbuser.get_front_data('msn', 'circleticket')
	
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
	
	def msn_create_circle(self, uuid: str, circle_name: str, owner_friendly: str, membership_access: int, request_membership_option: int, is_presence_enabled: bool) -> Optional[Tuple[str, str]]:
		with Session() as sess:
			head = self.get(uuid)
			if head is None: return None
			dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.circle_name).one_or_none()
			if dbcirclestore is not None: return None
			
			circle_id = '00000000-0000-0000-0009-' + misc.gen_uuid()[-12:]
			dbcirclestore = DBCircleStore(
				id = circle_id, circle_name = circle_name,
				owner_email = head.email, owner_friendly = owner_friendly, membership_access = membership_access, request_membership_option = request_membership_option, is_presence_enabled = is_presence_enabled,
				_user_memberships = { head.email: { 'membership_role': int(ABRelationshipRole.Admin), 'membership_status': int(ABRelationshipState.Accepted) }, },
			)
			sess.add(dbcirclestore)
			
			circleuser_uuid = misc.gen_uuid()
			circledbuser = DBUser(
				uuid = circleuser_uuid, networkid = NetworkID.CIRCLE, email = '{}@live.com'.format(circle_id), relay = True, verified = False,
				name = circle_id, message = '',
				password = hasher.encode(gen_salt(length = 32)), groups = {}, contacts = {}, settings = {}, subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000'],
			)
			
			circleuser_abstore = DBABStore(
				member_uuid = circledbuser.uuid, ab_id = '00000000-0000-0000-0000-000000000000',
			)
			circleuser_abstore.date_last_modified = datetime.utcnow()
			
			circledbabmetadata = DBABMetadata(
				ab_id = circle_id, ab_type = 'Group',
			)
			circledbabstore = DBABStore(
				member_uuid = head.uuid, ab_id = circle_id,
			)
			sess.add_all([circledbuser, circleuser_abstore, circledbabmetadata, circledbabstore])
		return circle_id, circleuser_uuid
	
	def msn_get_circle_metadata(self, circle_id: str) -> Optional[CircleMetadata]:
		with Session() as sess:
			dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.id == circle_id).one_or_none()
			if dbcirclestore is None: return None
			
			return CircleMetadata(
				dbcirclestore.id, dbcirclestore.owner_email, dbcirclestore.owner_friendly, dbcirclestore.circle_name, dbcirclestore.date_last_modified,
				dbcirclestore.membership_access, dbcirclestore.request_membership_option, dbcirclestore.is_presence_enabled,
			)
	
	def msn_circle_set_user_membership(self, circle_id: str, email: str, member_role: Optional[ABRelationshipRole], member_status: Optional[ABRelationshipState]) -> bool:
		with Session() as sess:
			dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.id == circle_id).one_or_none()
			if dbcirclestore is None: return False
			
			dbcirclestore.set_user_membership(email, (int(member_role) if member_role is not None else None), (int(member_status) if member_status is not None else None))
			sess.add(dbcirclestore)
		return True
	
	def msn_check_circle_membership(self, circle_id: str, email: str) -> bool:
		with Session() as sess:
			dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.id == circle_id).one_or_none()
			if dbcirclestore is None: return False
			
			if dbcirclestore.get_user_membership(email) is None: return False
		return True
	
	def msn_get_circle_membership(self, circle_id: str, email: str) -> Optional[Dict[str, int]]:
		with Session() as sess:
			dbcirclestore = sess.query(DBCircleStore).filter(DBCircleStore.id == circle_id).one_or_none()
			if dbcirclestore is None: return None
			
			return dbcirclestore.get_user_membership(email)
	
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
	
	def yahoo_get_aliases(self, uuid: str) -> List[YahooAlias]:
		with Session() as sess:
			aliases = sess.query(DBYahooAlias).filter(DBYahooAlias.owner_uuid == uuid)
			tmp_aliases = [
				YahooAlias(
					alias.yid_alias, alias.is_activated,
				)
				for alias in aliases
			]
			return tmp_aliases
	
	def yahoo_add_alias(self, uuid: str, alias: str) -> None:
		with Session() as sess:
			dbyahooalias = DBYahooAlias(owner_uuid = uuid)
			dbyahooalias.yid_alias = alias
			sess.add(dbyahooalias)
			
			yahooalias_user = DBUser(
				uuid = misc.gen_uuid(), networkid = NetworkID.YAHOO, email = alias + '@yahoo.com', relay = True, verified = False,
				name = alias, message = '',
				password = hasher.encode(gen_salt(length = 32)), groups = {}, contacts = {}, settings = {},
			)
			sess.add(yahooalias_user)
	
	def yahoo_check_alias(self, alias: str) -> bool:
		with Session() as sess:
			query = sess.query(DBYahooAlias).filter(DBYahooAlias.yid_alias == alias).one_or_none()
			if query is not None: return True
		return False
	
	def yahoo_delete_alias(self, uuid: str, alias: str) -> bool:
		with Session() as sess:
			alias_entry = sess.query(DBYahooAlias).filter(DBYahooAlias.owner_uuid == uuid, DBYahooAlias.yid_alias == alias).one_or_none()
			if alias_entry is None: return False
			sess.delete(alias_entry)
		return True
	
	def save_batch(self, to_save: List[Tuple[User, UserDetail, bool]]) -> None:
		with Session() as sess:
			for user, detail, message_temp in to_save:
				dbuser = sess.query(DBUser).filter(DBUser.uuid == user.uuid).one()
				dbuser.name = user.status.name
				if not message_temp: dbuser.message = user.status.message
				dbuser.settings = user.settings
				dbuser.groups = [{
					'id': g.id, 'name': g.name,
				} for g in detail.groups.values()]
				dbuser.contacts = [{
					'uuid': c.head.uuid, 'name': c.status.name, 'message': c.status.message,
					'lists': c.lists, 'groups': list(c.groups),
				} for c in detail.contacts.values()]
				dbuser.subscribed_ab_stores = list(detail.subscribed_ab_stores)
				sess.add(dbuser)