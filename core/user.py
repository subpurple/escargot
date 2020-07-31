from typing import Dict, Optional, List, Tuple, Any, TYPE_CHECKING
from datetime import datetime
from dateutil import parser as iso_parser
from pathlib import Path
from sqlalchemy import func
import json

from util.hash import hasher, hasher_md5, hasher_md5crypt
from util import misc

from .conn import Conn
from .db import (
	User as DBUser, UserContact as DBUserContact, GroupChat as DBGroupChat,
	GroupChatMembership as DBGroupChatMembership,
)
from .models import (
	User, Contact, ContactDetail, ContactLocation, ContactGroupEntry, UserStatus, UserDetail, GroupChat,
	GroupChatMembership, GroupChatRole, GroupChatState, Group, RoamingInfo, OIM,
)

if TYPE_CHECKING:
	from .backend import BackendSession

class UserService:
	__slots__ = ('_conn', '_cache_by_uuid', '_groupchat_cache_by_chat_id')
	
	_conn: Conn
	_cache_by_uuid: Dict[str, Optional[User]]
	_groupchat_cache_by_chat_id: Dict[str, Optional[GroupChat]]
	
	def __init__(self, conn: Conn) -> None:
		self._conn = conn
		self._cache_by_uuid = {}
		self._groupchat_cache_by_chat_id = {}
	
	def login(self, email: str, pwd: str) -> Optional[str]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(func.lower(DBUser.email) == email.lower()).one_or_none()
			if dbuser is None: return None
			if not hasher.verify(pwd, dbuser.password): return None
			return dbuser.uuid
	
	def msn_login_md5(self, email: str, md5_hash: str) -> Optional[str]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(func.lower(DBUser.email) == email.lower()).one_or_none()
			if dbuser is None: return None
			if not hasher_md5.verify_hash(md5_hash, dbuser.get_front_data('msn', 'pw_md5') or ''): return None
			return dbuser.uuid
	
	def msn_get_md5_salt(self, email: str) -> Optional[str]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(func.lower(DBUser.email) == email.lower()).one_or_none()
			if dbuser is None: return None
			pw_md5 = dbuser.get_front_data('msn', 'pw_md5')
		if pw_md5 is None: return None
		return hasher.extract_salt(pw_md5)
	
	def yahoo_get_md5_password(self, uuid: str) -> Optional[bytes]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return hasher_md5.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5_unsalted') or '')
	
	def yahoo_get_md5crypt_password(self, uuid: str) -> Optional[bytes]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			return hasher_md5crypt.extract_hash(dbuser.get_front_data('ymsg', 'pw_md5crypt') or '')
	
	def update_date_login(self, uuid: str) -> None:
		with self._conn.session() as sess:
			sess.query(DBUser).filter(DBUser.uuid == uuid).update({
				'date_login': datetime.utcnow(),
			})
	
	def get_uuid(self, email: str) -> Optional[str]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(func.lower(DBUser.email) == email.lower()).one_or_none()
			if dbuser is None: return None
			return dbuser.uuid
	
	def get_uuid_username(self, username: str) -> Optional[str]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(func.lower(DBUser.username) == username.lower()).one_or_none()
			if dbuser is None: return None
			return dbuser.uuid
	
	def get(self, uuid: str) -> Optional[User]:
		if uuid not in self._cache_by_uuid:
			self._cache_by_uuid[uuid] = self._get_uncached(uuid)
		return self._cache_by_uuid[uuid]
	
	def _get_uncached(self, uuid: str) -> Optional[User]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			status = UserStatus(dbuser.friendly_name or dbuser.email)
			return User(dbuser.id, dbuser.uuid, dbuser.email, dbuser.username, dbuser.verified, status, dbuser.settings, dbuser.date_created)
	
	def get_detail(self, uuid: str) -> Optional[UserDetail]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == uuid).one_or_none()
			if dbuser is None: return None
			detail = UserDetail()
			for g in dbuser.groups:
				grp = Group(**g)
				detail._groups_by_id[grp.id] = grp
				detail._groups_by_uuid[grp.uuid] = grp
			contacts = sess.query(DBUserContact).filter(DBUserContact.user_id == dbuser.id)
			for c in contacts:
				ctc_head = self.get(c.uuid)
				if ctc_head is None: continue
				status = UserStatus(c.name or ctc_head.email)
				ctc_groups = { ContactGroupEntry(
					ctc_head.uuid, group_entry['id'], group_entry['uuid'],
				) for group_entry in c.groups }
				c_detail = ContactDetail(
					c.index_id, birthdate = c.birthdate, anniversary = c.anniversary, notes = c.notes,
					first_name = c.first_name, middle_name = c.middle_name, last_name = c.last_name,
					nickname = c.nickname, primary_email_type = c.primary_email_type,
					personal_email = c.personal_email, work_email = c.work_email, im_email = c.im_email,
					other_email = c.other_email, home_phone = c.home_phone, work_phone = c.work_phone,
					fax_phone = c.fax_phone, pager_phone = c.pager_phone, mobile_phone = c.mobile_phone,
					other_phone = c.other_phone, personal_website = c.personal_website,
					business_website = c.business_website,
				)
				c_detail.locations = {
					type: ContactLocation(
						type, name = location.get('name'), street = location.get('street'), city = location.get('city'),
						state = location.get('state'), country = location.get('country'), zip_code = location.get('zip_code'),
					)
					for type, location in c.locations.items()
				}
				ctc = Contact(
					ctc_head, ctc_groups, c.lists, status, c_detail, is_messenger_user = c.is_messenger_user, pending = c.pending,
				)
				detail.contacts[ctc.head.uuid] = ctc
		return detail
	
	def get_roaming_info(self, user: User) -> Optional[RoamingInfo]:
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.id == user.id).one_or_none()
			if dbuser is None: return None
			return RoamingInfo(dbuser.name, dbuser.name_last_modified, dbuser.message, dbuser.message_last_modified)
	
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
		
		if not oim_path.is_file():
			return None
		
		json_oim = json.loads(oim_path.read_text())
		if not isinstance(json_oim, dict):
			return None
		
		oim = OIM(
			json_oim['uuid'], json_oim['run_id'], json_oim['from'], json_oim['from_username'], json_oim['from_friendly']['friendly_name'],
			user.email, iso_parser.parse(json_oim['sent']),
			json_oim['message']['text'], json_oim['message']['utf8'],
			headers = json_oim['headers'],
			from_friendly_encoding = json_oim['from_friendly']['encoding'], from_friendly_charset = json_oim['from_friendly']['charset'],
			from_user_id = json_oim['from_user_id'], origin_ip = json_oim['origin_ip'], oim_proxy = json_oim['proxy'],
		)
		if mark_read:
			json_oim['is_read'] = True
			oim_path.write_text(json.dumps(json_oim))
		
		return oim
	
	def save_oim(
		self, bs: 'BackendSession', recipient_uuid: str, run_id: str, origin_ip: str, message: str, utf8: bool, *,
		from_friendly: Optional[str] = None, from_friendly_charset: str = 'utf-8', from_friendly_encoding: str = 'B',
		from_user_id: Optional[str] = None, headers: Dict[str, str] = {}, oim_proxy: Optional[str] = None,
	) -> None:
		assert bs is not None
		user = bs.user
		
		path = _get_oim_path(recipient_uuid)
		path.mkdir(parents = True, exist_ok = True)
		oim_uuid = misc.gen_uuid().upper()
		oim_path = path / oim_uuid
		
		if oim_path.is_file():
			return
		
		oim_json = {} # type: Dict[str, Any]
		oim_json['uuid'] = oim_uuid
		oim_json['run_id'] = run_id
		oim_json['from'] = user.email
		oim_json['from_username'] = user.username
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
			oim_json['uuid'], oim_json['run_id'], oim_json['from'], oim_json['from_username'], oim_json['from_friendly']['friendly_name'],
			user.email, iso_parser.parse(oim_json['sent']), oim_json['message']['text'], oim_json['message']['utf8'],
			headers = oim_json['headers'], from_friendly_encoding = oim_json['from_friendly']['encoding'],
			from_friendly_charset = oim_json['from_friendly']['charset'], from_user_id = oim_json['from_user_id'],
			origin_ip = oim_json['origin_ip'], oim_proxy = oim_json['proxy'],
		)
		
		bs.me_contact_notify_oim(recipient_uuid, oim)
	
	def delete_oim(self, recipient_uuid: str, uuid: str) -> None:
		oim_path = _get_oim_path(recipient_uuid) / uuid
		if not oim_path.is_file():
			return
		oim_path.unlink()
	
	def create_groupchat(self, user: User, name: str, owner_friendly: str, membership_access: int) -> str:
		with self._conn.session() as sess:
			chat_id = misc.gen_uuid()[-12:]
			
			dbgroupchat = DBGroupChat(
				chat_id = chat_id, name = name,
				owner_id = user.id, owner_uuid = user.uuid, owner_friendly = owner_friendly,
				membership_access = membership_access, request_membership_option = 0,
			)
			sess.add(dbgroupchat)
			
			dbgroupchatmembership = DBGroupChatMembership(
				chat_id = chat_id, member_id = user.id, member_uuid = user.uuid,
				role = int(GroupChatRole.Admin), state = int(GroupChatState.Accepted), blocking = False,
			)
			sess.add(dbgroupchatmembership)
		
		return chat_id
	
	def get_groupchat(self, chat_id: str) -> Optional[GroupChat]:
		if chat_id not in self._groupchat_cache_by_chat_id:
			self._groupchat_cache_by_chat_id[chat_id] = self._get_groupchat_uncached(chat_id)
		return self._groupchat_cache_by_chat_id[chat_id]
	
	def _get_groupchat_uncached(self, chat_id: str) -> Optional[GroupChat]:
		with self._conn.session() as sess:
			dbgroupchat = sess.query(DBGroupChat).filter(DBGroupChat.chat_id == chat_id).one_or_none()
			if dbgroupchat is None: return None
			
			groupchat = GroupChat(
				dbgroupchat.chat_id, dbgroupchat.name, dbgroupchat.owner_id, dbgroupchat.owner_uuid, dbgroupchat.owner_friendly,
				 dbgroupchat.membership_access, dbgroupchat.request_membership_option,
			)
			
			dbgroupchatmemberships = sess.query(DBGroupChatMembership).filter(DBGroupChatMembership.chat_id == chat_id)
			for dbgroupchatmembership in dbgroupchatmemberships:
				head = self.get(dbgroupchatmembership.member_uuid)
				if head is None: continue
				
				groupchat.memberships[head.uuid] = GroupChatMembership(
					dbgroupchat.chat_id, head,
					GroupChatRole(dbgroupchatmembership.role), GroupChatState(dbgroupchatmembership.state),
					blocking = dbgroupchatmembership.blocking,
					inviter_uuid = dbgroupchatmembership.inviter_uuid, inviter_email = dbgroupchatmembership.inviter_email,
					inviter_name = dbgroupchatmembership.inviter_name, invite_message = dbgroupchatmembership.invite_message,
				)
		
		return groupchat
	
	def get_all_groupchats(self) -> List[GroupChat]:
		groupchats = []
		
		with self._conn.session() as sess:
			dbgroupchats = sess.query(DBGroupChat)
			
			for dbgroupchat in dbgroupchats:
				groupchat = self.get_groupchat(dbgroupchat.chat_id)
				if groupchat is None: continue
				
				groupchats.append(groupchat)
		
		return groupchats
	
	def get_groupchat_batch(self, user: User) -> List[GroupChat]:
		groupchats = []
		
		with self._conn.session() as sess:
			dbgroupchats = sess.query(DBGroupChat)
			
			for dbgroupchat in dbgroupchats:
				if dbgroupchat.chat_id in self._groupchat_cache_by_chat_id:
					groupchat = self._groupchat_cache_by_chat_id[dbgroupchat.chat_id]
					if groupchat is None: continue
					if user.uuid not in groupchat.memberships: continue
				else:
					dbgroupchatmembership = sess.query(DBGroupChatMembership).filter(
						DBGroupChatMembership.chat_id == dbgroupchat.chat_id, DBGroupChatMembership.member_uuid == user.uuid
					).one_or_none()
					if dbgroupchatmembership is None:
						continue
				
				groupchat = self.get_groupchat(dbgroupchat.chat_id)
				if groupchat is None: continue
				
				groupchats.append(groupchat)
		
		return groupchats
	
	def save_groupchat_batch(self, to_save: List[Tuple[str, GroupChat]]) -> None:
		with self._conn.session() as sess:
			dbgroupchatmemberships_to_add = []
			for chat_id, groupchat in to_save:
				dbgroupchat = sess.query(DBGroupChat).filter(DBGroupChat.chat_id == chat_id).one()
				dbgroupchat.name = groupchat.name
				dbgroupchat.membership_access = groupchat.membership_access
				dbgroupchat.request_membership_option = groupchat.request_membership_option
				sess.add(dbgroupchat)
				
				dbgroupchatmemberships = sess.query(DBGroupChatMembership).filter(DBGroupChatMembership.chat_id == chat_id)
				for tmp in dbgroupchatmemberships:
					if tmp.member_uuid not in groupchat.memberships:
						sess.delete(tmp)
				for membership in groupchat.memberships.values():
					dbgroupchatmembership = sess.query(DBGroupChatMembership).filter(
						DBGroupChatMembership.chat_id == chat_id, DBGroupChatMembership.member_uuid == membership.head.uuid
					).one_or_none()
					if dbgroupchatmembership is None:
						dbgroupchatmembership = DBGroupChatMembership(
							chat_id = chat_id, member_id = membership.head.id, member_uuid = membership.head.uuid,
						)
					dbgroupchatmembership.role = int(membership.role)
					dbgroupchatmembership.state = int(membership.state)
					dbgroupchatmembership.blocking = membership.blocking
					dbgroupchatmembership.inviter_uuid = membership.inviter_uuid
					dbgroupchatmembership.inviter_email = membership.inviter_email
					dbgroupchatmembership.inviter_name = membership.inviter_name
					dbgroupchatmembership.invite_message = membership.invite_message
					dbgroupchatmemberships_to_add.append(dbgroupchatmembership)
				sess.add_all(dbgroupchatmemberships_to_add)
	
	def save_batch(self, to_save: List[Tuple[User, UserDetail]]) -> None:
		with self._conn.session() as sess:
			for user, detail in to_save:
				dbusercontacts_to_add = []
				
				dbuser = sess.query(DBUser).filter(DBUser.uuid == user.uuid).one()
				dbuser.friendly_name = user.status.name
				dbuser.groups = [{
					'id': g.id, 'uuid': g.uuid,
					'name': g.name, 'is_favorite': g.is_favorite,
				} for g in detail._groups_by_id.values()]
				dbuser.settings = user.settings
				sess.add(dbuser)
				
				dbusercontacts = sess.query(DBUserContact).filter(DBUserContact.user_id == user.id)
				for tmp in dbusercontacts:
					if tmp.uuid not in detail.contacts:
						sess.delete(tmp)
				for c in detail.contacts.values():
					dbusercontact = sess.query(DBUserContact).filter(
						DBUserContact.user_id == user.id, DBUserContact.contact_id == c.head.id
					).one_or_none()
					if dbusercontact is None:
						dbusercontact = DBUserContact(
							user_id = user.id, contact_id = c.head.id, user_uuid = user.uuid, uuid = c.head.uuid, index_id = c.detail.index_id,
						)
					
					dbusercontact.name = c.status.name
					dbusercontact.lists = c.lists
					dbusercontact.groups = [{
						'id': group.id, 'uuid': group.uuid,
					} for group in c._groups.copy()]
					dbusercontact.is_messenger_user = c.is_messenger_user
					dbusercontact.pending = c.pending
					dbusercontact.birthdate = c.detail.birthdate
					dbusercontact.anniversary = c.detail.anniversary
					dbusercontact.notes = c.detail.notes
					dbusercontact.first_name = c.detail.first_name
					dbusercontact.middle_name = c.detail.middle_name
					dbusercontact.last_name = c.detail.last_name
					dbusercontact.nickname = c.detail.nickname
					dbusercontact.primary_email_type = c.detail.primary_email_type
					dbusercontact.personal_email = c.detail.personal_email
					dbusercontact.work_email = c.detail.work_email
					dbusercontact.im_email = c.detail.im_email
					dbusercontact.other_email = c.detail.other_email
					dbusercontact.home_phone = c.detail.home_phone
					dbusercontact.work_phone = c.detail.work_phone
					dbusercontact.fax_phone = c.detail.fax_phone
					dbusercontact.pager_phone = c.detail.pager_phone
					dbusercontact.mobile_phone = c.detail.mobile_phone
					dbusercontact.other_phone = c.detail.other_phone
					dbusercontact.personal_website = c.detail.personal_website
					dbusercontact.business_website = c.detail.business_website
					dbusercontact.locations = {
						location.type: {
							'name': location.name, 'street': location.street, 'city': location.city, 'state': location.state,
							'country': location.country, 'zip_code': location.zip_code,
						} for location in c.detail.locations.values()
					}
					
					dbusercontacts_to_add.append(dbusercontact)
				if dbusercontacts_to_add:
					sess.add_all(dbusercontacts_to_add)
	
	def save_single_roaming(self, user: User, to_save: Dict[str, Any]) -> None:
		updated = False
		
		with self._conn.session() as sess:
			dbuser = sess.query(DBUser).filter(DBUser.uuid == user.uuid).one()
			if 'name' in to_save:
				dbuser.name = to_save['name']
				dbuser.name_last_modified = datetime.utcnow()
				updated = True
			if 'message' in to_save:
				dbuser.message = to_save['message']
				dbuser.message_last_modified = datetime.utcnow()
				updated = True
			
			if updated:
				sess.add(dbuser)

def _get_oim_path(recipient_uuid: str) -> Path:
	return Path('storage/oim') / recipient_uuid
