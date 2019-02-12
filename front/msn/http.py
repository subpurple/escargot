from typing import Optional, Any, Dict, Tuple
from datetime import datetime, timedelta
from pytz import timezone
from enum import IntEnum
from urllib.parse import unquote
import lxml
import re
import secrets
import base64
import os
import time
from markupsafe import Markup
from aiohttp import web

import settings
from core import models, event
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
from .misc import gen_mail_data, cid_format
import util.misc

LOGIN_PATH = '/login'
TMPL_DIR = 'front/msn/tmpl'
PP = 'Passport1.4 '

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'msn', TMPL_DIR, globals = {
		'date_format': _date_format,
		'cid_format': cid_format,
		'bool_to_str': _bool_to_str,
		'contact_is_favorite': _contact_is_favorite,
		'datetime': datetime,
	})
	
	# MSN >= 5
	app.router.add_get('/nexus-mock', handle_nexus)
	app.router.add_get('/rdr/pprdr.asp', handle_nexus)
	app.router.add_get(LOGIN_PATH, handle_login)
	
	# MSN >= 6
	app.router.add_get('/etc/MsgrConfig', handle_msgrconfig)
	app.router.add_post('/etc/MsgrConfig', handle_msgrconfig)
	app.router.add_get('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_get('/config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/config/MsgrConfig.asmx', handle_msgrconfig)
	
	# MSN >= 7.5
	app.router.add_route('OPTIONS', '/NotRST.srf', handle_not_rst)
	app.router.add_post('/NotRST.srf', handle_not_rst)
	app.router.add_post('/RST.srf', handle_rst)
	app.router.add_post('/RST2.srf', lambda req: handle_rst(req, rst2 = True))
	
	# MSN 8.1.0178
	# TODO: Use SOAP library for ABService, SharingService, and StorageService.
	app.router.add_post('/abservice/SharingService.asmx', handle_abservice)
	app.router.add_post('/abservice/abservice.asmx', handle_abservice)
	app.router.add_post('/storageservice/SchematizedStore.asmx', handle_storageservice)
	app.router.add_get('/storage/usertile/{uuid}/static', handle_usertile)
	app.router.add_get('/storage/usertile/{uuid}/small', lambda req: handle_usertile(req, small = True))
	app.router.add_post('/rsi/rsi.asmx', handle_rsi)
	app.router.add_post('/OimWS/oim.asmx', handle_oim)
	
	# Misc
	app.router.add_get('/etc/debug', handle_debug)

async def handle_abservice(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	header, action, bs, token = await _preprocess_soap(req)
	if bs is None:
		raise web.HTTPForbidden()
	action_str = _get_tag_localname(action)
	if _find_element(action, 'deltasOnly') or _find_element(action, 'DeltasOnly'):
		return render(req, 'msn:abservice/Fault.fullsync.xml', { 'faultactor': action_str })
	now_str = _date_format(datetime.utcnow())
	user = bs.user
	detail = user.detail
	cachekey = secrets.token_urlsafe(172)
	
	#print(_xml_to_string(action))
	backend: Backend = req.app['backend']
	
	try:
		if action_str == 'FindMembership':
			return render(req, 'msn:sharing/FindMembershipResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'user': user,
				'detail': detail,
				'lists': [models.Lst.AL, models.Lst.BL, models.Lst.RL, models.Lst.PL],
				'now': now_str,
			})
		if action_str == 'AddMember':
			email = None # type: Optional[str]
			
			memberships = action.findall('.//{*}memberships/{*}Membership')
			for membership in memberships:
				lst = models.Lst.Parse(str(_find_element(membership, 'MemberRole')))
				assert lst is not None
				members = membership.findall('.//{*}Members/{*}Member')
				for member in members:
					member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
					if member_type == 'PassportMember':
						if _find_element(member, 'Type') == 'Passport' and _find_element(member, 'State') == 'Accepted':
							email = _find_element(member, 'PassportName')
					elif member_type == 'EmailMember':
						if _find_element(member, 'Type') == 'Email' and _find_element(member, 'State') == 'Accepted':
							email = _find_element(member, 'Email')
					contact_uuid = backend.util_get_uuid_from_email(email)
					assert contact_uuid is not None
					try:
						bs.me_contact_add(contact_uuid, lst, name = email)
					except:
						pass
			return render(req, 'msn:sharing/AddMemberResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'DeleteMember':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			email = None # type: Optional[str]
			
			memberships = action.findall('.//{*}memberships/{*}Membership')
			for membership in memberships:
				lst = models.Lst.Parse(str(_find_element(membership, 'MemberRole')))
				assert lst is not None
				members = membership.findall('.//{*}Members/{*}Member')
				for member in members:
					member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
					if member_type == 'PassportMember':
						if _find_element(member, 'Type') == 'Passport' and _find_element(member, 'State') == 'Accepted':
							contact_uuid = _find_element(member, 'MembershipId').split('/', 1)[1]
					elif member_type == 'EmailMember':
						if _find_element(member, 'Type') == 'Email' and _find_element(member, 'State') == 'Accepted':
							email = _find_element(member, 'Email')
							contact_uuid = backend.util_get_uuid_from_email(email)
							assert contact_uuid is not None
					if contact_uuid not in detail.contacts:
						return render(req, 'msn:sharing/Fault.memberdoesnotexist.xml', status = 500)
					try:
						bs.me_contact_remove(contact_uuid, lst)
					except:
						pass
			return render(req, 'msn:sharing/DeleteMemberResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		
		if action_str == 'ABFindAll':
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			ab_type, user_creator, ab_created, ab_last_modified, ab_contacts = backend.user_service.get_ab_contents(ab_id, user)
			
			return render(req, 'msn:abservice/ABFindAllResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'user_creator': user_creator,
				'user_creator_detail': user_creator.detail,
				'ab_contacts': ab_contacts,
				'now': now_str,
				'ab_id': ab_id,
				'ab_type': ab_type,
				'ab_last_modified': ab_last_modified,
				'ab_created': ab_created,
			})
		if action_str == 'ABFindContactsPaged':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'ABId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			#circle_info = [(
			#	backend.user_service.msn_get_circle_metadata(circle_id), backend.user_service.msn_get_circle_membership(circle_id, user.email),
			#) for circle_id in detail.subscribed_ab_stores if circle_id.startswith('00000000-0000-0000-0009')]
			
			ab_type, user_creator, ab_created, ab_last_modified, ab_contacts = backend.user_service.get_ab_contents(ab_id, user)
			
			return render(req, 'msn:abservice/ABFindContactsPagedResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'user_creator': user_creator,
				'user_creator_detail': user_creator.detail,
				'ab_contacts': ab_contacts,
				'now': now_str,
				#'circle_info': circle_info,
				#'ABRelationshipRole': models.ABRelationshipRole,
				#'ABRelationshipState': models.ABRelationshipState,
				#'signedticket': gen_signedticket_xml(user, backend),
				'ab_id': ab_id,
				'ab_type': ab_type,
				'ab_created': ab_created,
				'ab_last_modified': ab_last_modified,
			})
		if action_str == 'ABContactAdd':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ctc = None
			ctc_updated = False
			annotations_dict = {}
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			contact = _find_element(action, 'contacts/Contact')
			
			if contact is None:
				return web.HTTPInternalServerError()
			
			type = _find_element(contact, 'contactType') or 'Regular'
			email = _find_element(contact, 'passportName')
			if '@' not in email:
				return render(req, 'msn:abservice/Fault.emailmissingatsign.xml', status = 500)
			elif '.' not in email:
				return render(req, 'msn:abservice/Fault.emailmissingdot.xml', status = 500)
			
			contact_uuid = backend.util_get_uuid_from_email(email)
			if contact_uuid is None:
				return render(req, 'msn:abservice/Fault.invaliduser.xml', {
					'email': email,
				}, status = 500)
			
			ctc_ab = backend.user_service.ab_get_entry_by_email(ab_id, email, type, user)
			if ctc_ab is not None:
				return render(req, 'msn:abservice/Fault.contactalreadyexists.xml', status = 500)
			
			if ab_id == '00000000-0000-0000-0000-000000000000':
				ctc = detail.contacts.get(contact_uuid)
				if ctc:
					groups = set([group.uuid for group in ctc._groups.copy()])
			if not ctc:
				groups = set()
			annotations = contact.findall('.//{*}annotations/{*}Annotation')
			if annotations:
				annotations_dict = {_find_element(annotation, 'Name'): _find_element(annotation, 'Value') for annotation in annotations}
			is_messenger_user = _find_element(contact, 'isMessengerUser')
			ctc_ab = models.ABContact(
				('Regular' if type == 'LivePending' else type), util.misc.gen_uuid(), email, email, groups,
				member_uuid = contact_uuid, is_messenger_user = is_messenger_user, annotations = annotations_dict,
			)
			await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
					
			return render(req, 'msn:abservice/ABContactAddResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'contact_uuid': ctc_ab.uuid,
			})
		if action_str == 'ABContactDelete':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ctc = None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			contacts = action.findall('.//{*}contacts/{*}Contact')
			for contact in contacts:
				contact_uuid = _find_element(contact, 'contactId')
				assert contact_uuid is not None
				backend.user_service.ab_delete_entry(ab_id, contact_uuid, user)
			return render(req, 'msn:abservice/ABContactDeleteResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'ABContactUpdate':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ctc = None
			ctc_ab = None
			contacts_to_update = []
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			contacts = action.findall('.//{*}contacts/{*}Contact')
			for contact in contacts:
				contact_info = _find_element(contact, 'contactInfo')
				if _find_element(contact_info, 'contactType') == 'Me':
					contact_uuid = user.uuid
				else:
					contact_uuid = _find_element(contact, 'contactId')
				if not contact_uuid:
					return web.HTTPInternalServerError()
				properties_changed = _find_element(contact, 'propertiesChanged')
				if not contact_uuid or not properties_changed:
					return web.HTTPInternalServerError()
				properties_changed = str(properties_changed).strip().split(' ')
				for i, contact_property in enumerate(properties_changed):
					if contact_property not in _CONTACT_PROPERTIES:
						return web.HTTPInternalServerError()
				for contact_property in properties_changed:
					if contact_property == 'DisplayName':
						ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
						if not ctc_ab:
							return web.HTTPInternalServerError()
						property = _find_element(contact, 'displayName')
						ctc_ab.name = property
						contacts_to_update.append(ctc_ab)
					if contact_property == 'IsMessengerUser':
						ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
						if not ctc_ab:
							return web.HTTPInternalServerError()
						property = _find_element(contact, 'isMessengerUser')
						if property is None:
							return web.HTTPInternalServerError()
						ctc_ab.is_messenger_user = property
						contacts_to_update.append(ctc_ab)
					if contact_property == 'Annotation':
						if _find_element(contact_info, 'contactType') != 'Me':
							ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
							if not ctc_ab:
								return web.HTTPInternalServerError()
						annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
						for annotation in annotations:
							name = _find_element(annotation, 'Name')
							if name not in _ANNOTATION_NAMES:
								return web.HTTPInternalServerError()
							value = _find_element(annotation, 'Value')
							value = _bool_to_str(value) if isinstance(value, bool) else str(_find_element(annotation, 'Value'))
							
							if name == 'MSN.IM.GTC':
								try:
									if value == '':
										gtc = GTCAnnotation.Empty
									else:
										gtc = GTCAnnotation(value)
								except ValueError:
									return web.HTTPInternalServerError()
								
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'gtc': None if gtc is GTCAnnotation.Empty else gtc.name })
							if name == 'MSN.IM.BLP':
								try:
									if value == '':
										blp = BLPAnnotation.Empty
									else:
										blp = BLPAnnotation(value)
								except ValueError:
									return web.HTTPInternalServerError()
								
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'blp': None if blp is BLPAnnotation.Empty else blp.name })
							if name == 'MSN.IM.MPOP':
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'mpop': None if value in ('',None) else value })
							if name == 'MSN.IM.RoamLiveProperties':
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'rlp': value })
							if ctc_ab:
								if ctc_ab.annotations is None:
									ctc_ab.annotations = {}
								ctc_ab.annotations.update({name: value})
								if value == '':
									del ctc_ab.annotations[name]
					# TODO: Contact details
				contacts_to_update.append(ctc_ab)
			bs.me_ab_contact_edit(contacts_to_update, ab_id)
			
			return render(req, 'msn:abservice/ABContactUpdateResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'ABGroupAdd':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores or ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			name = _find_element(action, 'name')
			is_favorite = _find_element(action, 'IsFavorite')
			
			if len(name) > MAX_GROUP_NAME_LENGTH:
				return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
					'action_str': 'ABGroupAdd',
				}, status = 500)
			
			if detail.get_groups_by_name(name) is not None:
				return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
					'action_str': 'ABGroupAdd',
				}, status = 500)
			
			group = bs.me_group_add(name)
			return render(req, 'msn:abservice/ABGroupAddResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'group_id': group.uuid,
			})
		if action_str == 'ABGroupUpdate':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores or ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			groups = action.findall('.//{*}groups/{*}Group')
			for group in groups:
				group_id = str(_find_element(group, 'groupId'))
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
				group_info = group.find('.//{*}groupInfo')
				properties_changed = _find_element(group, 'propertiesChanged')
				if not properties_changed:
					return web.HTTPInternalServerError()
				properties_changed = str(properties_changed).strip().split(' ')
				for i, contact_property in enumerate(properties_changed):
					if contact_property not in _CONTACT_PROPERTIES:
						return web.HTTPInternalServerError()
				for contact_property in properties_changed:
					if contact_property == 'GroupName':
						name = str(_find_element(group_info, 'name'))
						if name is None:
							return web.HTTPInternalServerError()
						elif len(name) > MAX_GROUP_NAME_LENGTH:
							return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
								'action_str': 'ABGroupUpdate',
							}, status = 500)
						
						if detail.get_groups_by_name(name) is not None:
							return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
								'action_str': 'ABGroupUpdate',
							}, status = 500)
					is_favorite = _find_element(group_info, 'IsFavorite')
					if is_favorite is not None:
						if not isinstance(is_favorite, bool):
							return web.HTTPInternalServerError()
			for group in groups:
				group_id = str(_find_element(group, 'groupId'))
				g = detail.get_group_by_id(group_id)
				group_info = group.find('.//{*}groupInfo')
				properties_changed = _find_element(group, 'propertiesChanged')
				properties_changed = str(properties_changed).strip().split(' ')
				for contact_property in properties_changed:
					if contact_property == 'GroupName':
						name = str(_find_element(group_info, 'name'))
						bs.me_group_edit(group_id, new_name = name)
					# What's the `propertiesChanged` value for the favourite setting? Check for the node for now
					is_favorite = _find_element(group_info, 'IsFavorite')
					if is_favorite is not None:
						bs.me_group_edit(group_id, is_favorite = is_favorite)
			return render(req, 'msn:abservice/ABGroupUpdateResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'ABGroupDelete':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores or ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
			for group_id in group_ids:
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
			for group_id in group_ids:
				bs.me_group_remove(group_id)
			return render(req, 'msn:abservice/ABGroupDeleteResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'ABGroupContactAdd':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores or ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
			
			for group_id in group_ids:
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
			
			if _find_element(action, 'contactInfo') is not None:
				email = _find_element(action, 'passportName')
				if email is None:
					email = _find_element(action, 'email')
					if email is None:
						return web.HTTPInternalServerError()
				type = _find_element(action, 'contactType') or 'Regular'
				contact_uuid = backend.util_get_uuid_from_email(email)
				assert contact_uuid is not None
				
				ctc = detail.contacts.get(contact_uuid)
				if ctc is not None and ctc.lists & models.Lst.FL:
					for group_id in group_ids:
						for group in ctc._groups.copy():
							if group.uuid == group_id:
								return web.HTTPInternalServerError()
				
				ctc_ab = backend.user_service.ab_get_entry_by_email(ab_id, email, ('Regular' if type == 'LivePending' else type), user)
				
				if ctc_ab is not None:
					for group_id in group_ids:
						if group_id in ctc_ab.groups:
							return web.HTTPInternalServerError()
				
				is_messenger_user = _find_element(action, 'isMessengerUser') or False
				
				for group_id in group_ids:
					try:
						ctc, _ = bs.me_contact_add(contact_uuid, models.Lst.FL, group_id = group_id, name = email)
					except:
						return web.HTTPInternalServerError()
				
				if ctc_ab is None:
					ctc_ab = models.ABContact(
						('Regular' if type == 'LivePending' else type), util.misc.gen_uuid(), ctc.head.email, ctc.status.name, set(),
						member_uuid = contact_uuid, is_messenger_user = is_messenger_user,
					)
				
				for group_id in group_ids:
					ctc_ab.groups.add(group_id)
				
				await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
			else:
				contact_uuid = _find_element(action, 'contactId')
				assert contact_uuid is not None
				ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
				if ctc_ab is None:
					print('AB not found')
					return web.HTTPInternalServerError()
				else:
					for group_id in group_ids:
						if group_id in ctc_ab.groups:
							return web.HTTPInternalServerError()
				
				ctc = detail.contacts.get(ctc_ab.member_uuid)
				if ctc is None or not ctc.lists & models.Lst.FL:
					if ctc is None:
						print('ctc does not exist')
					else:
						print('ctc not on FL')
					return web.HTTPInternalServerError()
				else:
					for group_id in group_ids:
						for group in ctc._groups.copy():
							if group.uuid == group_id:
								return web.HTTPInternalServerError()
				
				for group_id in group_ids:
					bs.me_group_contact_add(group_id, ctc.head.uuid)
					ctc_ab.groups.add(group_id)
				
				await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
			return render(req, 'msn:abservice/ABGroupContactAddResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'contact_uuid': contact_uuid,
			})
		if action_str == 'ABGroupContactDelete':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores or ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
			
			for group_id in group_ids:
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
			
			contact_uuid = _find_element(action, 'contactId')
			assert contact_uuid is not None
			ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
			if ctc_ab is None:
				return web.HTTPInternalServerError()
			else:
				for group_id in group_ids:
					if group_id not in ctc_ab.groups:
						return web.HTTPInternalServerError()
			
			ctc = detail.contacts.get(ctc_ab.member_uuid)
			if ctc is not None:
				if ctc.lists & models.Lst.FL:
					for group_id in group_ids:
						ctc_in_group = False
						for group in ctc._groups.copy():
							if group.uuid == group_id:
								ctc_in_group = True
						if not ctc_in_group:
							return web.HTTPInternalServerError()
					for group_id in group_ids:
						bs.me_group_contact_remove(group_id, ctc.head.uuid)
						ctc_ab.groups.remove(group_id)
			
			await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
			return render(req, 'msn:abservice/ABGroupContactDeleteResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		#if action_str == 'CreateCircle':
		#	user = bs.user
		#	
		#	if _find_element(action, 'Domain') == 1 and _find_element(action, 'HostedDomain') == 'live.com' and _find_element(action, 'Type') == 2 and isinstance(_find_element(action, 'IsPresenceEnabled'), bool):
		#		membership_access = int(_find_element(action, 'MembershipAccess'))
		#		request_membership_option = int(_find_element(action, 'RequestMembershipOption'))
		#		
		#		circle_name = str(_find_element(action, 'DisplayName'))
		#		circle_owner_friendly = str(_find_element(action, 'PublicDisplayName'))
		#		
		#		circle_id, circle_acc_uuid = backend.user_service.msn_create_circle(user.uuid, circle_name, circle_owner_friendly, membership_access, request_membership_option, _find_element(action, 'IsPresenceEnabled'))
		#		if circle_id is None:
		#			return web.HTTPInternalServerError()
		#		
		#		bs.me_subscribe_ab(circle_id)
		#		# Add circle relay to contact list
		#		bs.me_contact_add(circle_acc_uuid, models.Lst.FL, add_to_ab = False)
		#		bs.me_contact_add(circle_acc_uuid, models.Lst.AL)
		#		
		#		# Add self to individual AB
		#		# TODO: Proper hidden representative of circle creator (does this display them in the roster?)
		#		#ctc_self_hidden_representative = models.ABContact(
		#		#	'Circle', util.misc.gen_uuid(), user.email, user.status.name or user.email, set(), {
		#		#		models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
		#		#			models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
		#		#			user.status.name, models.RelationshipInfo(
		#		#				models.ABRelationshipType.Circle, models.ABRelationshipRole.Admin, models.ABRelationshipState.Accepted,
		#		#			),
		#		#		)
		#		#	},
		#		#	member_uuid = user.uuid, is_messenger_user = True,
		#		#)
		#		#await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_self_hidden_representative], }, user)
		#		backend.user_service.msn_update_circleticket(user.uuid, cid_format(user.uuid, decimal = True))
		#		
		#		try:
		#			return render(req, 'msn:abservice/CreateCircleResponse.xml', {
		#				'cachekey': cachekey,
		#				'host': settings.LOGIN_HOST,
		#				'session_id': util.misc.gen_uuid(),
		#				'circle_id': circle_id,
		#			})
		#		finally:
		#			_, _, _, ab_last_modified, _ = backend.user_service.get_ab_contents(circle_id, user)
		#			bs.evt.msn_on_notify_ab(cid_format(user.uuid, decimal = True), _date_format(ab_last_modified))
		#			
		#			#circle_bs = backend.login(backend.util_get_uuid_from_email('{}@live.com'.format(circle_id), models.NetworkID.CIRCLE), None, CircleBackendEventHandler(), only_once = True)
		#			#if circle_bs is not None:
		#			#	if bs.front_data.get('msn_circle_sessions') is None:
		#			#		bs.front_data['msn_circle_sessions'] = { circle_bs }
		#			#	else:
		#			#		bs.front_data['msn_circle_sessions'].add(circle_bs)
		#			#	circle_bs.front_data['msn_circle_roster'] = { bs }
		#			#	circle_bs.me_update({ 'substatus': models.Substatus.Online })
		#if action_str == 'CreateContact':
		#	user = bs.user
		#	detail = user.detail
		#	assert detail is not None
		#	
		#	ab_id = str(_find_element(action, 'ABId'))
		#	contact_email = _find_element(action, 'Email')
		#	
		#	if ab_id not in detail.subscribed_ab_stores:
		#		return web.HTTPInternalServerError()
		#	
		#	_, user_creator, _, _, _ = backend.user_service.get_ab_contents(ab_id, user)
		#	
		#	contact_uuid = backend.util_get_uuid_from_email(contact_email)
		#	if contact_uuid is None:
		#		return web.HTTPInternalServerError()
		#	
		#	ctc_ab = models.ABContact(
		#		('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), util.misc.gen_uuid(), contact_email, contact_email, set(), {},
		#		member_uuid = contact_uuid, is_messenger_user = True,
		#	)
		#	
		#	await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
		#	
		#	return render(req, 'msn:abservice/CreateContactResponse.xml', {
		#		'cachekey': cachekey,
		#		'host': settings.LOGIN_HOST,
		#		'session_id': util.misc.gen_uuid(),
		#		'ab_id': ab_id,
		#		'contact': ctc_ab,
		#		'user_creator_detail': user_creator.detail,
		#	})
		#if action_str == 'ManageWLConnection':
		#	#TODO: Finish `NetworkInfo` implementation for circles
		#	user = bs.user
		#	detail = user.detail
		#	assert detail is not None
		#	
		#	ab_id = str(_find_element(action, 'ABId'))
		#	
		#	if ab_id not in detail.subscribed_ab_stores:
		#		return web.HTTPInternalServerError()
		#	
		#	contact_uuid = _find_element(action, 'contactId')
		#	
		#	_, user_creator, _, _, _ = backend.user_service.get_ab_contents(ab_id, user)
		#	
		#	ctc = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
		#	
		#	if ctc is None or ctc.networkinfos.get(models.NetworkID.WINDOWS_LIVE) is not None:
		#		return web.HTTPInternalServerError()
		#	
		#	if _find_element(action, 'connection') == True:
		#		try:
		#			relationship_type = models.ABRelationshipType(_find_element(action, 'relationshipType'))
		#			relationship_role = models.ABRelationshipRole(_find_element(action, 'relationshipRole'))
		#			wl_action = int(_find_element(action, 'action'))
		#		except ValueError:
		#			return web.HTTPInternalServerError()
		#		
		#		if relationship_type == models.ABRelationshipType.Circle:
		#			if relationship_role == models.ABRelationshipRole.Member:
		#				if wl_action == 1:
		#					membership_set = backend.user_service.msn_circle_set_user_membership(ab_id, ctc.email, member_role = models.ABRelationshipRole.StatePendingOutbound, member_state = models.ABRelationshipState.Accepted)
		#					if not membership_set:
		#						return web.HTTPInternalServerError()
		#					
		#					ctc.networkinfos[models.NetworkID.WINDOWS_LIVE] = models.NetworkInfo(
		#						models.NetworkID.WINDOWS_LIVE, 'WL', ctc.email,
		#						ctc.name or ctc.email, models.RelationshipInfo(
		#							models.ABRelationshipType.Circle, models.ABRelationshipRole.StatePendingOutbound, models.ABRelationshipState.Accepted,
		#						),
		#					)
		#					
		#					if not ctc.member_uuid:
		#						return web.HTTPInternalServerError()
		#					ctc_head = backend._load_user_record(ctc.member_uuid)
		#					if ctc_head is None:
		#						return web.HTTPInternalServerError()
		#					ctc_ab_contact = backend.user_service.ab_get_entry_by_email('00000000-0000-0000-0000-000000000000', user.email, ('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), ctc_head)
		#					if ctc_ab_contact:
		#						return web.HTTPInternalServerError()
		#					ctc_ab_contact = models.ABContact(
		#						('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), util.misc.gen_uuid(), user.email, user.status.name or user.email, set(), {
		#							models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
		#								models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
		#								user.status.name, models.RelationshipInfo(
		#									models.ABRelationshipType.Circle, models.ABRelationshipRole.StatePendingOutbound, models.ABRelationshipState.Accepted,
		#								),
		#							),
		#						},
		#						member_uuid = user.uuid, is_messenger_user = True,
		#					)
		#					
		#					await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc] }, user)
		#					await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab_contact] }, ctc_head)
		#				
		#					if ab_id != '00000000-0000-0000-0000-000000000000':
		#						bs.other_subscribe_ab(ab_id, ctc_head)
		#	
		#	return render(req, 'msn:abservice/ManageWLConnection/ManageWLConnection.xml', {
		#		'cachekey': cachekey,
		#		'host': settings.LOGIN_HOST,
		#		'session_id': util.misc.gen_uuid(),
		#		'ab_id': ab_id,
		#		'contact': ctc,
		#		'user_creator_detail': user_creator.detail,
		#	})
		if action_str in { 'UpdateDynamicItem' }:
			# TODO: UpdateDynamicItem
			return _unknown_soap(req, header, action, expected = True)
	except Exception as ex:
		import traceback
		return render(req, 'msn:Fault.generic.xml', {
			'exception': traceback.format_exc(),
		})
	
	return _unknown_soap(req, header, action)

async def handle_storageservice(req):
	header, action, bs, token = await _preprocess_soap(req)
	assert bs is not None
	action_str = _get_tag_localname(action)
	now_str = _date_format(datetime.utcnow())
	timestamp = int(time.time())
	user = bs.user
	cachekey = secrets.token_urlsafe(172)
	
	cid = cid_format(user.uuid)
	
	if action_str == 'GetProfile':
		return render(req, 'msn:storageservice/GetProfileResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
			'now': now_str,
			'timestamp': timestamp,
			'host': settings.STORAGE_HOST
		})
	if action_str == 'FindDocuments':
		# TODO: FindDocuments
		return render(req, 'msn:storageservice/FindDocumentsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str == 'UpdateProfile':
		# TODO: UpdateProfile
		return render(req, 'msn:storageservice/UpdateProfileResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str == 'DeleteRelationships':
		# TODO: DeleteRelationships
		return render(req, 'msn:storageservice/DeleteRelationshipsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str == 'CreateDocument':
		return handle_create_document(req, action, user, cid, token, timestamp)
	if action_str == 'CreateRelationships':
		# TODO: CreateRelationships
		return render(req, 'msn:storageservice/CreateRelationshipsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str in { 'ShareItem' }:
		# TODO: ShareItem
		return _unknown_soap(req, header, action, expected = True)
	return _unknown_soap(req, header, action)

async def handle_rsi(req: web.Request) -> web.Response:
	header, action, bs, token = await _preprocess_soap_rsi(req)
	
	if token is None or bs is None:
		return render(req, 'msn:oim/Fault.validation.xml', status = 500)
	action_str = _get_tag_localname(action)
	
	# Since valtron's MSIDCRL solution does not supply the ticket ('t='/'p='), we can't go any further with authentication or action supplication.
	# Keep the code for when we can get the original MSIDCRL DLL modified for Escargot use.
	# Return 'Fault.unsupported.xml' for now.
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })
	
	user = bs.user
	
	backend = req.app['backend']
	
	if action_str == 'GetMetadata':
		return render(req, 'msn:oim/GetMetadataResponse.xml', {
			'md': gen_mail_data(user, backend, on_ns = False, e_node = False).decode('utf-8'),
		})
	if action_str == 'GetMessage':
		oim_uuid = _find_element(action, 'messageId')
		oim_markAsRead = _find_element(action, 'alsoMarkAsRead')
		oim_message = backend.user_service.msn_get_oim_message_by_uuid(user.email, oim_uuid, oim_markAsRead is True)
		return render(req, 'msn:oim/GetMessageResponse.xml', {
			'oim_data': oim_message,
		})
	if action_str == 'DeleteMessages':
		messageIds = action.findall('.//{*}messageId/{*}messageIds')
		for messageId in messageIds:
			isValidDeletion = backend.user_service.msn_delete_oim(messageId)
			if not isValidDeletion:
				return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		bs.evt.msn_on_oim_deletion()
		return render(req, 'msn:oim/DeleteMessagesResponse.xml')
	
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

async def handle_oim(req: web.Request) -> web.Response:
	# However, the ticket is present when this service is used. Odd.
	
	header, body_msgtype, body_content, bs, token = await _preprocess_soap_oimws(req)
	soapaction = req.headers.get('SOAPAction').strip('"')
	
	lockkey_result = header.find('.//{*}Ticket').get('lockkey')
	
	if bs is None or lockkey_result == '':
		return render(req, 'msn:oim/Fault.authfailed.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
			'authTypeNode': (Markup('<TweenerChallenge xmlns="http://messenger.msn.com/ws/2004/09/oim/">ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1</TweenerChallenge>') if soapaction.startswith('http://messenger.msn.com/ws/2004/09/') else Markup('<SSOChallenge xmlns="http://messenger.live.com/ws/2006/09/oim/">?MBI_KEY_OLD</SSOChallenge>')),
		}, status = 500)
	
	backend: Backend = req.app['backend']
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	friendlyname = header.find('.//{*}From').get('friendlyName')
	email = header.find('.//{*}From').get('memberName')
	recipient = header.find('.//{*}To').get('memberName')
	
	recipient_uuid = backend.util_get_uuid_from_email(recipient)
	
	if email != user.email or recipient_uuid is None or not _is_on_al(recipient_uuid, detail):
		return render(req, 'msn:oim/Fault.unavailable.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	peername = req.transport.get_extra_info('peername')
	if peername:
		host = peername[0]
	else:
		host = '127.0.0.1'
	
	oim_msg_seq = _find_element(header, 'Sequence/MessageNumber')
	
	oim_proxy_string = header.find('.//{*}From').get('proxy')
	
	oim_sent_date = datetime.utcnow()
	oim_sent_date_email = oim_sent_date.astimezone(timezone('US/Pacific'))
	
	oim_content = body_content.strip().replace('\n', '\r\n')
	
	oim_run_id_start = (oim_content.find('X-OIM-Run-Id: ') + 15)
	oim_run_id_stop = oim_run_id_start + 36
	oim_run_id = oim_content[oim_run_id_start:oim_run_id_stop]
	
	oim_header_body = oim_content.split('\r\n\r\n')
	oim_header_body[0] = OIM_HEADER_PRE.format(
		pst1 = oim_sent_date_email.strftime('%a, %d %b %Y %H:%M:%S -0800'), friendly = friendlyname,
		sender = user.email, recipient = recipient, ip = host, oimproxy = oim_proxy_string,
	) + oim_header_body[0]
	oim_header_body[0] += OIM_HEADER_REST.format(
		utc = oim_sent_date.strftime('%d %b %Y %H:%M:%S.%f')[:25] + ' (UTC)', ft = _datetime_to_filetime(oim_sent_date),
		pst2 = oim_sent_date_email.strftime('%d %b %Y %H:%M:%S -0800'),
	)
	
	oim_content = '\r\n\r\n'.join(oim_header_body)
	
	backend.user_service.msn_save_oim(oim_run_id, int(oim_msg_seq), oim_content, user.email, friendlyname, recipient, oim_sent_date)
	bs.me_contact_notify_oim(recipient_uuid, oim_run_id)
	
	return render(req, 'msn:oim/StoreResponse.xml', {
		'seq': oim_msg_seq,
		'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
	})

def _is_on_al(uuid: str, detail: models.UserDetail):
	contact = detail.contacts.get(uuid)
	if detail.settings.get('BLP', 'AL') is 'AL' and (contact is None or contact.lists != models.Lst.BL):
		return True
	elif detail.settings.get('BLP', 'AL') is 'BL' and contact is not None and contact.lists != models.Lst.BL:
		return True
	return False

def _unknown_soap(req: web.Request, header: Any, action: Any, *, expected: bool = False) -> web.Response:
	action_str = _get_tag_localname(action)
	if not expected and settings.DEBUG:
		print("Unknown SOAP:", action_str)
		print(_xml_to_string(header))
		print(_xml_to_string(action))
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

def _datetime_to_filetime(dt_time: datetime) -> str:
	filetime_result = round(((dt_time.timestamp() * 10000000) + 116444736000000000) + (dt_time.microsecond * 10))
	
	# (DWORD)ll
	filetime_high = filetime_result & 0xFFFFFFFF
	filetime_low = filetime_result >> 32
	
	filetime_high_hex = hex(filetime_high)[2:]
	filetime_high_hex = '0' * (8 % len(filetime_high_hex)) + filetime_high_hex
	filetime_low_hex = hex(filetime_low)[2:]
	filetime_low_hex = '0' * (8 % len(filetime_low_hex)) + filetime_low_hex
	
	return filetime_high_hex.upper() + ':' + filetime_low_hex.upper()

def _xml_to_string(xml: Any) -> str:
	return lxml.etree.tostring(xml, pretty_print = True).decode('utf-8')

def _parse_cookies(cookie_string: Optional[str]) -> Dict[str, Any]:
	cookie_dict = {}
	cookie_data = None
	
	if not cookie_string:
		return {}
	
	cookies = cookie_string.split(';')
	
	for cookie in cookies:
		if not cookie: continue
		cookie_kv = cookie.split('=', 1)
		if len(cookie_kv) == 2:
			cookie_data = cookie_kv[1]
		cookie_dict[cookie_kv[0]] = cookie_data
	
	return cookie_dict

async def _preprocess_soap(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	mspauth = False
	
	body = await req.read()
	root = parse_xml(body)
	
	token = _find_element(root, 'TicketToken')
	if token is None:
		token = req.cookies.get('MSPAuth')
		if token is None:
			token = _parse_cookies(req.headers.get('Cookie')).get('MSPAuth')
		if token is not None:
			mspauth = True
	if token is None:
		raise web.HTTPInternalServerError()
		
	if token[0:2] == 't=':
		token = token[2:22]
	elif mspauth:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	backend_sess = backend.util_get_sess_by_token(token)
	
	header = _find_element(root, 'Header')
	action = _find_element(root, 'Body/*[1]')
	if settings.DEBUG and settings.DEBUG_MSNP: print('Action: {}'.format(_get_tag_localname(action)))
	
	return header, action, backend_sess, token

async def _preprocess_soap_rsi(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token_tag = root.find('.//{*}PassportCookie/{*}*[1]')
	if _get_tag_localname(token_tag) is not 't':
		token = None
	# TODO: Due to valtron's MSIDCRL DLL not supplying the ticket on certain SOAP services, ignore ticket for now.
	# Also, either implement the functions for those services or patch the original MSIDCRL.
	token = token_tag.text
	if token is not None and token[0:2] == 't=':
		token = token[2:22]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = _find_element(root, 'Header')
	action = _find_element(root, 'Body/*[1]')
	if settings.DEBUG and settings.DEBUG_MSNP: print('Action: {}'.format(_get_tag_localname(action)))
	
	return header, action, bs, token

async def _preprocess_soap_oimws(req: web.Request) -> Tuple[Any, Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token = root.find('.//{*}Ticket').get('passport')
	if token[0:2] == 't=':
		token = token[2:22]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = _find_element(root, 'Header')
	body_msgtype = _find_element(root, 'Body/MessageType')
	body_content = _find_element(root, 'Body/Content')
	
	return header, body_msgtype, body_content, bs, token

def _get_tag_localname(elm: Any) -> str:
	return lxml.etree.QName(elm.tag).localname

def _find_element(xml: Any, query: str) -> Any:
	thing = xml.find('.//{*}' + query.replace('/', '/{*}'))
	if isinstance(thing, lxml.objectify.StringElement):
		thing = str(thing)
	elif isinstance(thing, lxml.objectify.BoolElement):
		thing = bool(thing)
	return thing

async def handle_msgrconfig(req: web.Request) -> web.Response:
	if req.method == 'POST':
		body = await req.read()
	else:
		body = None
	msgr_config = _get_msgr_config(req, body)
	if msgr_config == 'INVALID_VER':
		return web.Response(status = 500)
	return web.HTTPOk(content_type = 'text/xml', text = msgr_config)

def _get_msgr_config(req: web.Request, body: Optional[bytes]) -> str:
	query = req.query
	result = None # type: Optional[str]
	
	if query.get('ver') is not None:
		if re.match(r'[^\d\.]', query.get('ver')):
			return 'INVALID_VER'
		
		config_ver = query.get('ver').split('.', 4)
		if 5 <= int(config_ver[0]) <= 7:
			with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
				envelope = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
		elif int(config_ver[0]) == 8:
			with open(TMPL_DIR + '/MsgrConfig.wlm.8.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = config.format(tabs = config_tabs)
		elif int(config_ver[0]) >= 14:
			with open(TMPL_DIR + '/MsgrConfig.wlm.14.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = config.format(tabs = config_tabs)
	elif body is not None:
		with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
			envelope = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
			config = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			config_tabs = fh.read()
		result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
	
	return result or ''

async def handle_nexus(req: web.Request) -> web.Response:
	return web.HTTPOk(headers = {
		'PassportURLs': 'DALogin=https://{}{}'.format(settings.LOGIN_HOST, LOGIN_PATH),
	})

async def handle_login(req: web.Request) -> web.Response:
	tmp = _extract_pp_credentials(req.headers.get('Authorization'))
	if tmp is None:
		token = None
	else:
		email, pwd = tmp
		token = _login(req, email, pwd)
	if token is None:
		raise web.HTTPUnauthorized(headers = {
			'WWW-Authenticate': '{}da-status=failed'.format(PP),
		})
	return web.HTTPOk(headers = {
		'Authentication-Info': '{}da-status=success,from-PP=\'{}\''.format(PP, token),
	})

async def handle_not_rst(req: web.Request) -> web.Response:
	if req.method == 'OPTIONS':
		return web.HTTPOk(headers = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST',
			'Access-Control-Allow-Headers': 'X-User, X-Password, Content-Type',
			'Access-Control-Expose-Headers': 'X-Token',
			'Access-Control-Max-Age': str(86400),
		})
	
	email = req.headers.get('X-User')
	pwd = req.headers.get('X-Password')
	token = _login(req, email, pwd, lifetime = 86400)
	headers = {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'POST',
		'Access-Control-Expose-Headers': 'X-Token',
	}
	if token is not None:
		headers['X-Token'] = token
	return web.HTTPOk(headers = headers)

async def handle_rst(req: web.Request, rst2: bool = False) -> web.Response:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	email = _find_element(root, 'Username')
	pwd = str(_find_element(root, 'Password'))

	if email is None or pwd is None:
		raise web.HTTPBadRequest()
	
	backend: Backend = req.app['backend']
	
	token = _login(req, email, pwd, lifetime = 86400)
	
	uuid = backend.util_get_uuid_from_email(email)
	
	if token is not None and uuid is not None:
		now = datetime.utcfromtimestamp(backend.auth_service.get_token_expiry('nb/login', token) - 86400)
		timez = _date_format(now)
		tomorrowz = _date_format((now + timedelta(days = 1)))
		time_5mz = _date_format((now + timedelta(minutes = 5)))
		
		# load PUID and CID, assume them to be the same for our purposes
		cid = cid_format(uuid)
		
		peername = req.transport.get_extra_info('peername')
		if peername:
			host = peername[0]
		else:
			host = '127.0.0.1'
		
		# get list of requested domains
		domains = root.findall('.//{*}Address')
		domains.pop(0) # ignore Passport token request
		
		tmpl = req.app['jinja_env'].get_template(('msn:RST/RST2.token.xml' if rst2 else 'msn:RST/RST.token.xml'))
		# collect tokens for requested domains
		tokenxmls = [tmpl.render(
			i = i + 1,
			domain = domain,
			timez = timez,
			tomorrowz = tomorrowz,
			pptoken1 = token,
		) for i, domain in enumerate(domains)]
		
		tmpl = req.app['jinja_env'].get_template(('msn:RST/RST2.xml' if rst2 else 'msn:RST/RST.xml'))
		return web.HTTPOk(
			content_type = 'text/xml',
			text = (tmpl.render(
				puidhex = cid.upper(),
				time_5mz = time_5mz,
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = host,
				pptoken1 = token,
				tokenxml = Markup(''.join(tokenxmls)),
			) if rst2 else tmpl.render(
				puidhex = cid.upper(),
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = host,
				pptoken1 = token,
				tokenxml = Markup(''.join(tokenxmls)),
			)),
		)
	
	return render(req, 'msn:RST/RST.error.xml', {
		'timez': _date_format(datetime.utcnow()),
	}, status = 403)

def _get_storage_path(uuid: str) -> str:
	return 'storage/dp/{}/{}'.format(uuid[0:1], uuid[0:2])

def handle_create_document(req: web.Request, action: Any, user: models.User, cid: str, token: str, timestamp: int) -> web.Response:
	from PIL import Image
	
	# get image data
	name = _find_element(action, 'Name')
	streamtype = _find_element(action, 'DocumentStreamType')
	
	if streamtype == 'UserTileStatic':
		mime = _find_element(action, 'MimeType')
		data = _find_element(action, 'Data')
		data = base64.b64decode(data)
		
		# store display picture as file
		path = _get_storage_path(user.uuid)
		
		if not os.path.exists(path):
			os.makedirs(path)
		
		image_path = '{path}/{uuid}.{mime}'.format(
			path = path,
			uuid = user.uuid,
			mime = mime
		)
		
		fp = open(image_path, 'wb')
		fp.write(data)
		fp.close()
		
		image = Image.open(image_path)
		thumb = image.resize((21, 21))
		
		thumb_path = '{path}/{uuid}_thumb.{mime}'.format(
			path=path,
			uuid=user.uuid,
			mime=mime
		)
		
		thumb.save(thumb_path)
	
	return render(req, 'msn:storageservice/CreateDocumentResponse.xml', {
		'user': user,
		'cid': cid,
		'pptoken1': token,
		'timestamp': timestamp,
	})

async def handle_usertile(req: web.Request, small: bool = False) -> web.Response:
	uuid = req.match_info['uuid']
	storage_path = _get_storage_path(uuid)
	
	try:
		ext = os.listdir(storage_path)[0].split('.')[-1]
		image_path = os.path.join(storage_path, '{}{}.{}'.format(uuid, '_thumb' if small else '', ext))
		with open(image_path, 'rb') as file:
			return web.HTTPOk(content_type = 'image/{}'.format(ext), body = file.read())
	except FileNotFoundError:
		raise web.HTTPNotFound()

async def handle_debug(req: web.Request) -> web.Response:
	return render(req, 'msn:debug.html')

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	# This is only here because of `ABFindContactsPaged`, where WLM 2009 will encode the CircleTicket to Windows format (CR LF), and the ticket
	# data is Unix (LF).
	content = tmpl.render(**(ctxt or {})).replace('\n', '\r\n')
	return web.Response(status = status, content_type = content_type, text = content)

def _extract_pp_credentials(auth_str: str) -> Optional[Tuple[str, str]]:
	if auth_str is None:
		return None
	assert auth_str.startswith(PP)
	auth = {}
	for part in auth_str[len(PP):].split(','):
		parts = part.split('=', 1)
		if len(parts) == 2:
			auth[unquote(parts[0])] = unquote(parts[1])
	email = auth['sign-in']
	pwd = auth['pwd']
	return email, pwd

def _login(req, email: str, pwd: str, lifetime: int = 30) -> Optional[str]:
	backend: Backend = req.app['backend']
	uuid = backend.user_service.login(email, pwd)
	if uuid is None: return None
	return backend.auth_service.create_token('nb/login', uuid, lifetime = lifetime)

def _date_format(d: Optional[datetime], *, timezone: Optional[str] = None, Z: bool = True) -> Optional[str]:
	if d is None: return None
	if timezone:
		d = d.astimezone(timezone)
	if timezone:
		d_iso = '{}.{:03.0f}'.format(
			d.strftime('%Y-%m-%dT%H:%M:%S'), round(d.microsecond / 1000.0),
		)
		offset = d.strftime('%z')
		if re.match(r'([\+-]\d{4})$', offset):
			d_iso += '{}:{}'.format(
				offset[:3], offset[-2:],
			)
	else:
		d_iso = '{}{}'.format(
			d.isoformat()[0:19], ('Z' if Z else ''),
		)
	
	return d_iso

def _bool_to_str(b: bool) -> str:
	return 'true' if b else 'false'

def _contact_is_favorite(groups: Dict[str, models.Group], ctc: models.ABContact) -> bool:
	for group_id in ctc.groups:
		if group_id not in groups: continue
		if groups[group_id].is_favorite: return True
	return False

_CONTACT_PROPERTIES = (
	'Email', 'Number', 'Comment', 'DisplayName', 'ContactType', 'ContactEmail', 'ContactPhone', 'GroupName',
	'IsMessengerEnabled', 'IsMessengerUser', 'IsFavorite', 'HasSpace',
	'Annotation', 'Capability', 'MessengerMemberInfo',
)

_ANNOTATION_NAMES = (
	'MSN.IM.InviteMessage', 'MSN.IM.MPOP', 'MSN.IM.BLP', 'MSN.IM.GTC', 'MSN.IM.RoamLiveProperties',
	'MSN.IM.MBEA', 'MSN.IM.BuddyType', 'AB.NickName', 'AB.Profession', 'Live.Locale', 'Live.Profile.Expression.LastChanged',
	'Live.Passport.Birthdate', 'Live.Favorite.Order',
)

class GTCAnnotation(IntEnum):
	Empty = 0
	A = 1
	N = 2

class BLPAnnotation(IntEnum):
	Empty = 0
	AL = 1
	BL = 2

OIM_HEADER_PRE = '''X-Message-Info: cwRBnLifKNE8dVZlNj6AiX8142B67OTjG9BFMLMyzuui1H4Xx7m3NQ==
Received: from OIM-SSI02.phx.gbl ([65.54.237.206]) by oim1-f1.hotmail.com with Microsoft SMTPSVC(6.0.3790.211);
	 {pst1}
Received: from mail pickup service by OIM-SSI02.phx.gbl with Microsoft SMTPSVC;
	 {pst1}
From: {friendly} <{sender}>
To: {recipient}
Subject: 
X-OIM-originatingSource: {ip}
X-OIMProxy: {oimproxy}
'''

OIM_HEADER_REST = '''
Message-ID: <OIM-SSI02zDv60gxapz00061a8b@OIM-SSI02.phx.gbl>
X-OriginalArrivalTime: {utc} FILETIME=[{ft}]
Date: {pst2}
Return-Path: ndr@oim.messenger.msn.com'''
