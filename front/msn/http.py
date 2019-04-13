from typing import Optional, Any, Dict, Tuple
from datetime import datetime, timedelta
from enum import IntEnum
from email.parser import Parser
from email.header import decode_header
from urllib.parse import unquote
import lxml
import re
import secrets
import base64
import os
import time
from dateutil import parser as iso_parser
from markupsafe import Markup
from aiohttp import web

import settings
from core import models, event
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
from .misc import gen_mail_data, format_oim, cid_format
import util.misc

LOGIN_PATH = '/login'
TMPL_DIR = 'front/msn/tmpl'
PP = 'Passport1.4 '

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'msn', TMPL_DIR, globals = {
		'date_format': util.misc.date_format,
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
	backend: Backend = req.app['backend']
	
	header, action, bs, token = await _preprocess_soap(req)
	if bs is None:
		raise web.HTTPForbidden()
	action_str = _get_tag_localname(action)
	if _find_element(action, 'deltasOnly') or _find_element(action, 'DeltasOnly'):
		return render(req, 'msn:abservice/Fault.fullsync.xml', { 'faultactor': action_str })
	now_str = util.misc.date_format(datetime.utcnow())
	user = bs.user
	detail = user.detail
	cachekey = secrets.token_urlsafe(172)
	
	#print(_xml_to_string(action))
	
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
					assert email is not None
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
			
			email = None
			
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
							assert email is not None
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
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id not in detail.subscribed_ab_stores:
				return web.HTTPInternalServerError()
			
			tpl = backend.user_service.get_ab_contents(ab_id, user)
			assert tpl is not None
			ab_type, user_creator, ab_created, ab_last_modified, ab_contacts = tpl
			
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
			
			tpl = backend.user_service.get_ab_contents(ab_id, user)
			assert tpl is not None
			ab_type, user_creator, ab_created, ab_last_modified, ab_contacts = tpl
			
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
			
			ctc_updated = False
			head = None
			nickname = None
			
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
			
			type = _find_element(contact, 'contactType') or 'LivePending'
			email = _find_element(contact, 'passportName') or ''
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
			
			#TODO: How does `LivePending` work and how are we expected to switch it to `Regular` afterwards?
			
			if ab_id == '00000000-0000-0000-0000-000000000000':
				ctc = detail.contacts.get(contact_uuid)
				if ctc:
					groups = set([group.uuid for group in ctc._groups.copy()])
			if not ctc:
				groups = set()
			annotations = contact.findall('.//{*}annotations/{*}Annotation')
			annotations_dict = {}
			if annotations:
				for annotation in annotations:
					name = _find_element(annotation, 'Name')
					if name not in _ANNOTATION_NAMES:
						return web.HTTPInternalServerError()
					value = _find_element(annotation, 'Value')
					if name is 'AB.NickName':
						nickname = value
					else:
						annotations_dict[name] = value
			is_messenger_user = _find_element(contact, 'isMessengerUser')
			ctc_ab = models.ABContact(
				('Regular' if type == 'LivePending' else type), backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), email, email, groups,
				member_uuid = contact_uuid, nickname = nickname, is_messenger_user = is_messenger_user, annotations = {name: value for name, value in annotations_dict.items() if name.startswith('AB.') or name.startswith('Live.')},
			)
			await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
			
			#if ab_id == '00000000-0000-0000-0000-000000000000':
			#	if ctc:
			#		head = ctc.head
			#	else:
			#		head = backend._load_user_record(contact_uuid)
			#	assert head is not None
			#	ctc_me_ab = backend.user_service.ab_get_entry_by_email(ab_id, email, 'LivePending', head)
			#	ctc_me_new = False
			#	
			#	annotations_me = {}
			#	
			#	for name in annotations_dict.keys():
			#		if name == 'MSN.IM.InviteMessage':
			#			annotations_me[name] = annotations_dict[name]
			#	
			#	if ctc_me_ab is None:
			#		ctc_me_ab = models.ABContact(
			#			'LivePending', backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), user.email, user.email, set(),
			#			member_uuid = user.uuid, is_messenger_user = is_messenger_user, annotations = annotations_me,
			#		)
			#		ctc_me_new = True
			#	else:
			#		if ctc_me_ab.is_messenger_user:
			#			ctc_me_ab.name = user.status.name or user.email
			#			ctc_me_ab.annotations.update(annotations_me)
			#	
			#	await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab] }, head)
			#	
			#	tpl = backend.user_service.get_ab_contents(ab_id, head)
			#	assert tpl is not None
			#	_, user_creator, _, ab_last_modified, _ = tpl
			#	
			#	for ctc_sess in backend.util_get_sessions_by_user(head):
			#		ctc_sess.evt.msn_on_notify_ab(cid_format(head.uuid), str(util.misc.date_format(ab_last_modified or datetime.utcnow())))
			
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
		#if action_str == 'CreateContact':
		#	# Used as a step in Circle invites, but also used for regular contact adds in WLM 2011/2012
		#	user = bs.user
		#	detail = user.detail
		#	assert detail is not None
		#	
		#	ab_id = _find_element(action, 'ABId')
		#	if ab_id is not None:
		#		ab_id = str(ab_id)
		#	else:
		#		ab_id = '00000000-0000-0000-0000-000000000000'
		#	
		#	if ab_id not in detail.subscribed_ab_stores:
		#		return web.HTTPInternalServerError()
		#	
		#	contact_email = _find_element(action, 'Email')
		#	
		#	tpl = backend.user_service.get_ab_contents(ab_id, user)
		#	assert tpl is not None
		#	_, user_creator, _, _, _ = tpl
		#	
		#	contact_uuid = backend.util_get_uuid_from_email(contact_email)
		#	if contact_uuid is None:
		#		return web.HTTPInternalServerError()
		#	
		#	type = ('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'Regular')
		#	
		#	ctc_ab = backend.user_service.ab_get_entry_by_email(ab_id, contact_email, type, user)
		#	if ctc_ab is not None:
		#		# TODO: Error SOAP
		#		return web.HTTPInternalServerError()
		#	
		#	ctc_ab = models.ABContact(
		#		type, backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), contact_email, contact_email, set(),
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
				if contact_uuid is not user.uuid:
					ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
					if not ctc_ab:
						return web.HTTPInternalServerError()
				properties_changed = contact.find('./{*}propertiesChanged')
				if not properties_changed:
					return web.HTTPInternalServerError()
				properties_changed = str(properties_changed).strip().split(' ')
				for contact_property in properties_changed:
					if contact_property not in _CONTACT_PROPERTIES:
						return web.HTTPInternalServerError()
				
				for contact_property in properties_changed:
					if contact_property == 'Anniversary':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'Anniversary')
						# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
						try:
							if property not in (None,-1):
								property = str(property)
								property = datetime.strptime(property, '%Y/%m/%d')
						except:
							return web.HTTPInternalServerError()
					if contact_property == 'ContactBirthDate':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'birthdate')
						try:
							if property is not None:
								property = str(property)
								if property != '0001-01-01T00:00:00':
									if not property.endswith('Z'):
										return web.HTTPInternalServerError()
									property = iso_parser.parse(property)
						except:
							return web.HTTPInternalServerError()
					if contact_property == 'ContactLocation':
						assert ctc_ab is not None
						contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
						for contact_location in contact_locations:
							if str(_find_element(contact_location, 'contactLocationType')) not in ('ContactLocationPersonal','ContactLocationBusiness'):
								return web.HTTPInternalServerError()
							location_properties_changed = _find_element(contact_location, 'Changes')
							if location_properties_changed is None:
								return web.HTTPInternalServerError()
							location_properties_changed = str(location_properties_changed).strip().split(' ')
							for location_property in location_properties_changed:
								if location_property not in _CONTACT_LOCATION_PROPERTIES:
									return web.HTTPInternalServerError()
							for location_property in location_properties_changed:
								if location_property == 'Name' and str(_find_element(contact_location, 'contactLocationType')) != 'ContactLocationBusiness':
									return web.HTTPInternalServerError()
					if contact_property == 'IsMessengerUser':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'isMessengerUser')
						if property is None:
							return web.HTTPInternalServerError()
					if contact_property == 'ContactEmail':
						assert ctc_ab is not None
						contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
						for contact_email in contact_emails:
							email_properties_changed = _find_element(contact_email, 'propertiesChanged')
							if email_properties_changed is None:
								return web.HTTPInternalServerError()
							email_properties_changed = str(email_properties_changed).strip().split(' ')
							for email_property in email_properties_changed:
								if email_property not in _CONTACT_EMAIL_PROPERTIES:
									return web.HTTPInternalServerError()
							if str(_find_element(contact_email, 'contactEmailType')) not in ('ContactEmailPersonal','ContactEmailBusiness','ContactEmailMessenger','ContactEmailOther'):
								return web.HTTPInternalServerError()
					if contact_property == 'ContactPrimaryEmailType':
						assert ctc_ab is not None
						email_primary_type = str(_find_element(contact_info, 'primaryEmailType'))
						if email_primary_type not in ('Passport','ContactEmailPersonal','ContactEmailBusiness','ContactEmailOther'):
							return web.HTTPInternalServerError()
					if contact_property == 'ContactPhone':
						assert ctc_ab is not None
						contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
						for contact_phone in contact_phones:
							phone_properties_changed = _find_element(contact_phone, 'propertiesChanged')
							if phone_properties_changed is None:
								return web.HTTPInternalServerError()
							phone_properties_changed = str(phone_properties_changed).strip().split(' ')
							for phone_property in phone_properties_changed:
								if phone_property not in _CONTACT_PHONE_PROPERTIES:
									return web.HTTPInternalServerError()
							if str(_find_element(contact_phone, 'contactPhoneType')) not in ('ContactPhonePersonal','ContactPhoneBusiness','ContactPhoneMobile','ContactPhoneFax','ContactPhonePager','ContactPhoneOther'):
								return web.HTTPInternalServerError()
					if contact_property == 'ContactWebSite':
						assert ctc_ab is not None
						contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
						for contact_website in contact_websites:
							if str(_find_element(contact_website, 'contactWebSiteType')) not in ('ContactWebSitePersonal','ContactWebSiteBusiness'):
								return web.HTTPInternalServerError()
					if contact_property == 'Annotation':
						if _find_element(contact_info, 'contactType') != 'Me':
							if ctc_ab is None:
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
										gtc = GTCAnnotation(int(value))
								except ValueError:
									return web.HTTPInternalServerError()
							if name == 'MSN.IM.BLP':
								try:
									if value == '':
										blp = BLPAnnotation.Empty
									else:
										blp = BLPAnnotation(int(value))
								except ValueError:
									return web.HTTPInternalServerError()
					# TODO: Contact details
				if _find_element(contact_info, 'contactType') != 'Me':
					if ctc_ab is None:
						return web.HTTPInternalServerError()
			for contact in contacts:
				updated = False
				contact_info = _find_element(contact, 'contactInfo')
				if _find_element(contact_info, 'contactType') == 'Me':
					contact_uuid = user.uuid
				else:
					contact_uuid = _find_element(contact, 'contactId')
				if contact_uuid is not user.uuid and contact_uuid is not None:
					ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
				properties_changed = str(contact.find('./{*}propertiesChanged')).strip().split(' ')
				
				for contact_property in properties_changed:
					if contact_property == 'ContactFirstName':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'firstName')
						ctc_ab.first_name = property
						print('First name:', property)
						updated = True
					if contact_property == 'ContactLastName':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'lastName')
						ctc_ab.last_name = property
						print('Last name:', property)
						updated = True
					if contact_property == 'MiddleName':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'MiddleName')
						ctc_ab.middle_name = property
						print('Middle name:', property)
						updated = True
					if contact_property == 'Anniversary':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'Anniversary')
						# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
						if property not in (None,-1):
							property = str(property)
							property = datetime.strptime(property, '%Y/%m/%d')
						if property is -1:
							property = None
						ctc_ab.anniversary = property
						updated = True
					if contact_property == 'ContactBirthDate':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'birthdate')
						if property is not None:
							property = str(property)
							if property != '0001-01-01T00:00:00':
								property = iso_parser.parse(property)
							else:
								property = None
						ctc_ab.birthdate = property
						updated = True
					if contact_property == 'Comment':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'comment')
						if property is not None:
							property = str(property)
						ctc_ab.notes = property
						updated = True
					if contact_property == 'ContactLocation':
						assert ctc_ab is not None
						contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
						for contact_location in contact_locations:
							contact_location_type = str(_find_element(contact_location, 'contactLocationType'))
							location_properties_changed = str(_find_element(contact_location, 'Changes')).strip().split(' ')
							if contact_location_type not in ctc_ab.locations:
								ctc_ab.locations[contact_location_type] = models.ABContactLocation(contact_location_type)
							for location_property in location_properties_changed:
								if location_property == 'Name':
									property = _find_element(contact_location, 'name')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].name = property
									updated = True
								if location_property == 'Street':
									property = _find_element(contact_location, 'street')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].street = property
									updated = True
								if location_property == 'City':
									property = _find_element(contact_location, 'city')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].city = property
									updated = True
								if location_property == 'State':
									property = _find_element(contact_location, 'state')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].state = property
									updated = True
								if location_property == 'Country':
									property = _find_element(contact_location, 'country')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].country = property
									updated = True
								if location_property == 'PostalCode':
									property = _find_element(contact_location, 'postalCode')
									if property is not None:
										property = str(property)
									ctc_ab.locations[contact_location_type].zip_code = property
									updated = True
							if ctc_ab.locations[contact_location_type].street is None and ctc_ab.locations[contact_location_type].city is None and ctc_ab.locations[contact_location_type].state is None and ctc_ab.locations[contact_location_type].country is None and ctc_ab.locations[contact_location_type].zip_code is None:
								del ctc_ab.locations[contact_location_type]
								updated = True
					if contact_property == 'DisplayName':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'displayName')
						if property is not None:
							property = str(property)
						ctc_ab.name = property
						updated = True
					if contact_property == 'IsMessengerUser':
						assert ctc_ab is not None
						property = _find_element(contact_info, 'isMessengerUser')
						ctc_ab.is_messenger_user = property
						updated = True
					if contact_property == 'ContactEmail':
						assert ctc_ab is not None
						contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
						for contact_email in contact_emails:
							email_properties_changed = str(_find_element(contact_email, 'propertiesChanged')).strip().split(' ')
							for email_property in email_properties_changed:
								if email_property == 'Email':
									email = contact_email.find('./{*}email')
									if email is not None:
										email = str(email)
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailPersonal':
										ctc_ab.personal_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailBusiness':
										ctc_ab.work_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailMessenger':
										ctc_ab.im_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailOther':
										ctc_ab.other_email = email
									updated = True
					if contact_property == 'ContactPrimaryEmailType':
						assert ctc_ab is not None
						email_primary_type = str(_find_element(contact_info, 'primaryEmailType'))
						ctc_ab.primary_email_type = email_primary_type
						updated = True
					if contact_property == 'ContactPhone':
						assert ctc_ab is not None
						contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
						for contact_phone in contact_phones:
							phone_properties_changed = str(_find_element(contact_phone, 'propertiesChanged')).strip().split(' ')
							for phone_property in phone_properties_changed:
								if phone_property == 'Number':
									phone_number = contact_phone.find('./{*}number')
									if phone_number is not None:
										phone_number = str(phone_number)
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePersonal':
										ctc_ab.home_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneBusiness':
										ctc_ab.work_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneFax':
										ctc_ab.fax_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePager':
										ctc_ab.pager_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneMobile':
										ctc_ab.mobile_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneOther':
										ctc_ab.other_phone = phone_number
									updated = True
					if contact_property == 'ContactWebSite':
						assert ctc_ab is not None
						contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
						for contact_website in contact_websites:
							contact_website_type = str(_find_element(contact_website, 'contactWebSiteType'))
							website = str(_find_element(contact_website, 'webURL'))
							if contact_website_type == 'ContactWebSitePersonal':
								ctc_ab.personal_website = website
							if contact_website_type == 'ContactWebSiteBusiness':
								ctc_ab.business_website = website
							updated = True
					if contact_property == 'Annotation':
						if contact_uuid is not None:
							if _find_element(contact_info, 'contactType') != 'Me':
								ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
								if not ctc_ab:
									continue
						else:
							continue
						annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
						for annotation in annotations:
							name = _find_element(annotation, 'Name')
							value = _find_element(annotation, 'Value')
							value = _bool_to_str(value) if isinstance(value, bool) else str(_find_element(annotation, 'Value'))
							
							if name == 'MSN.IM.GTC':
								if value == '':
									gtc = GTCAnnotation.Empty
								else:
									gtc = GTCAnnotation(int(value))
								
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'gtc': None if gtc is GTCAnnotation.Empty else gtc.name })
								continue
							if name == 'MSN.IM.BLP':
								if value == '':
									blp = BLPAnnotation.Empty
								else:
									blp = BLPAnnotation(int(value))
								
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'blp': None if blp is BLPAnnotation.Empty else blp.name })
								continue
							if name == 'MSN.IM.MPOP':
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'mpop': None if value in ('', None) else value })
								continue
							if name == 'MSN.IM.RoamLiveProperties':
								if _find_element(contact_info, 'contactType') == 'Me':
									bs.me_update({ 'rlp': value })
								continue
							if name == 'AB.NickName':
								if ctc_ab:
									ctc_ab.nickname = value
									updated = True
								continue
							if name == 'Live.Profile.Expression.LastChanged':
								# TODO: What's this used for?
								continue
							if ctc_ab:
								if ctc_ab.annotations is None:
									ctc_ab.annotations = {}
								ctc_ab.annotations.update({name: value})
								if value == '':
									del ctc_ab.annotations[name]
						updated = True
					# TODO: Contact details
				if _find_element(contact_info, 'contactType') != 'Me' and updated:
					if ctc_ab is not None:
						contacts_to_update.append(ctc_ab)
			if contacts_to_update:
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
			
			if name == '(No Group)':
				return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
					'action_str': 'ABGroupAdd',
				}, status = 500)
			
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
			for group_elm in groups:
				group_id = str(_find_element(group_elm, 'groupId'))
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
				group_info = group_elm.find('.//{*}groupInfo')
				properties_changed = _find_element(group_elm, 'propertiesChanged')
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
						elif name == '(No Group)':
							return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
								'action_str': 'ABGroupUpdate',
							}, status = 500)
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
			for group_elm in groups:
				group_id = str(_find_element(group_elm, 'groupId'))
				g = detail.get_group_by_id(group_id)
				group_info = group_elm.find('.//{*}groupInfo')
				properties_changed = _find_element(group_elm, 'propertiesChanged')
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
						for group_contact_entry in ctc._groups:
							if group_contact_entry.uuid == group_id:
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
					assert ctc is not None
					ctc_ab = models.ABContact(
						('Regular' if type == 'LivePending' else type), backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), ctc.head.email, ctc.status.name, set(),
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
					return web.HTTPInternalServerError()
				else:
					for group_id in group_ids:
						if group_id in ctc_ab.groups:
							return web.HTTPInternalServerError()
				
				ctc = detail.contacts.get(ctc_ab.member_uuid or '')
				if ctc is None or not ctc.lists & models.Lst.FL:
					return web.HTTPInternalServerError()
				else:
					for group_id in group_ids:
						for group_contact_entry in ctc._groups:
							if group_contact_entry.uuid == group_id:
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
			
			ctc = detail.contacts.get(ctc_ab.member_uuid or '')
			if ctc is not None:
				if ctc.lists & models.Lst.FL:
					for group_id in group_ids:
						ctc_in_group = False
						for group_contact_entry in ctc._groups:
							if group_contact_entry.uuid == group_id:
								ctc_in_group = True
								break
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
		if action_str == 'CreateCircle':
			return render(req, 'msn:abservice/Fault.circlenolongersupported.xml', status = 500)
			
			#user = bs.user
			#
			#if _find_element(action, 'Domain') == 1 and _find_element(action, 'HostedDomain') == 'live.com' and _find_element(action, 'Type') == 2 and isinstance(_find_element(action, 'IsPresenceEnabled'), bool):
			#	membership_access = int(_find_element(action, 'MembershipAccess'))
			#	request_membership_option = int(_find_element(action, 'RequestMembershipOption'))
			#	
			#	circle_name = str(_find_element(action, 'DisplayName'))
			#	circle_owner_friendly = str(_find_element(action, 'PublicDisplayName'))
			#	
			#	circle_id, circle_acc_uuid = backend.user_service.msn_create_circle(user.uuid, circle_name, circle_owner_friendly, membership_access, request_membership_option, _find_element(action, 'IsPresenceEnabled'))
			#	if circle_id is None:
			#		return web.HTTPInternalServerError()
			#	
			#	bs.me_subscribe_ab(circle_id)
			#	# Add circle relay to contact list
			#	bs.me_contact_add(circle_acc_uuid, models.Lst.FL, add_to_ab = False)
			#	bs.me_contact_add(circle_acc_uuid, models.Lst.AL)
			#	
			#	# Add self to individual AB
			#	# TODO: Proper hidden representative of circle creator (does this display them in the roster?)
			#	#ctc_self_hidden_representative = models.ABContact(
			#	#	'Circle', backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), user.email, user.status.name or user.email, set(), {
			#	#		models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
			#	#			models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
			#	#			user.status.name, models.RelationshipInfo(
			#	#				models.ABRelationshipType.Circle, models.ABRelationshipRole.Admin, models.ABRelationshipState.Accepted,
			#	#			),
			#	#		)
			#	#	},
			#	#	member_uuid = user.uuid, is_messenger_user = True,
			#	#)
			#	#await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_self_hidden_representative], }, user)
			#	backend.user_service.msn_update_circleticket(user.uuid, cid_format(user.uuid, decimal = True))
			#	
			#	try:
			#		return render(req, 'msn:abservice/CreateCircleResponse.xml', {
			#			'cachekey': cachekey,
			#			'host': settings.LOGIN_HOST,
			#			'session_id': util.misc.gen_uuid(),
			#			'circle_id': circle_id,
			#		})
			#	finally:
			#		_, _, _, ab_last_modified, _ = backend.user_service.get_ab_contents(circle_id, user)
			#		bs.evt.msn_on_notify_ab(cid_format(user.uuid, decimal = True), util.misc.date_format(ab_last_modified))
			#		
			#		#circle_bs = backend.login(backend.util_get_uuid_from_email('{}@live.com'.format(circle_id), models.NetworkID.CIRCLE), None, CircleBackendEventHandler(), only_once = True)
			#		#if circle_bs is not None:
			#		#	if bs.front_data.get('msn_circle_sessions') is None:
			#		#		bs.front_data['msn_circle_sessions'] = { circle_bs }
			#		#	else:
			#		#		bs.front_data['msn_circle_sessions'].add(circle_bs)
			#		#	circle_bs.front_data['msn_circle_roster'] = { bs }
			#		#	circle_bs.me_update({ 'substatus': models.Substatus.Online })
		#if action_str == 'ManageWLConnection':
		#	#TODO: Finish `NetworkInfo` implementation for circles
		#	user = bs.user
		#	detail = user.detail
		#	assert detail is not None
		#	
		#	ab_id = _find_element(action, 'ABId')
		#	if ab_id is not None:
		#		ab_id = str(ab_id)
		#	else:
		#		ab_id = '00000000-0000-0000-0000-000000000000'
		#	
		#	if ab_id not in detail.subscribed_ab_stores:
		#		return web.HTTPInternalServerError()
		#	
		#	contact_uuid = _find_element(action, 'contactId')
		#	assert contact_uuid is not None
		#	
		#	tpl = backend.user_service.get_ab_contents(ab_id, user)
		#	assert tpl is not None
		#	_, user_creator, _, _, _ = tpl
		#	
		#	ctc_ab = backend.user_service.ab_get_entry_by_uuid(ab_id, contact_uuid, user)
		#	
		#	if ctc_ab is None or ctc_ab.networkinfos.get(models.NetworkID.WINDOWS_LIVE) is not None:
		#		return web.HTTPInternalServerError()
		#	
		#	if _find_element(action, 'connection') == True:
		#		try:
		#			relationship_type = models.ABRelationshipType(_find_element(action, 'relationshipType'))
		#			relationship_role = _find_element(action, 'relationshipRole')
		#			if relationship_role is not None:
		#				relationship_role = models.ABRelationshipRole(relationship_role)
		#			wl_action = int(_find_element(action, 'action'))
		#		except ValueError:
		#			return web.HTTPInternalServerError()
		#		
		#		if not ctc_ab.member_uuid:
		#			return web.HTTPInternalServerError()
		#		ctc_head = backend._load_user_record(ctc_ab.member_uuid)
		#		if ctc_head is None:
		#			return web.HTTPInternalServerError()
		#		
		#		tpl = backend.user_service.get_ab_contents(ab_id, ctc_head)
		#		assert tpl is not None
		#		_, ctc_creator_ab, _, ctc_ab_last_modified, _ = tpl
		#		
		#		if wl_action == 1:
		#			if relationship_type == models.ABRelationshipType.Circle:
		#				#membership_set = backend.user_service.msn_circle_set_user_membership(ab_id, ctc.email, member_role = models.ABRelationshipRole.StatePendingOutbound, member_state = models.ABRelationshipState.Accepted)
		#				#if not membership_set:
		#				#	return web.HTTPInternalServerError()
		#				return web.HTTPInternalServerError()
		#			
		#			if relationship_role != None:
		#				return web.HTTPInternalServerError()
		#			
		#			ctc_ab.networkinfos[models.NetworkID.WINDOWS_LIVE] = models.NetworkInfo(
		#				models.NetworkID.WINDOWS_LIVE, 'WL', ctc_ab.email,
		#				ctc_ab.name or ctc_ab.email, models.RelationshipInfo(
		#					relationship_type, models.ABRelationshipRole.Empty, models.ABRelationshipState.WaitingResponse,
		#				),
		#			)
		#			
		#			ctc_ab_contact = backend.user_service.ab_get_entry_by_email('00000000-0000-0000-0000-000000000000', user.email, ('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), ctc_head)
		#			if not ctc_ab_contact and not ab_id.startswith('00000000-0000-0000-0009'):
		#				ctc_ab_contact = backend.user_service.ab_get_entry_by_email('00000000-0000-0000-0000-000000000000', user.email, 'Live', ctc_head)
		#			if ctc_ab_contact:
		#				return web.HTTPInternalServerError()
		#			ctc_ab_contact = models.ABContact(
		#				('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), backend.user_service.gen_ab_entry_id(ab_id, user), util.misc.gen_uuid(), user.email, user.status.name or user.email, set(),
		#				networkinfos = {
		#					models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
		#						models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
		#						user.status.name, models.RelationshipInfo(
		#							relationship_type, models.ABRelationshipRole.Empty, models.ABRelationshipState.WaitingResponse,
		#						),
		#					),
		#				}, member_uuid = user.uuid, is_messenger_user = True,
		#			)
		#			
		#			await backend.user_service.mark_ab_modified_async(ab_id, { 'contacts': [ctc_ab] }, user)
		#			await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab_contact] }, ctc_head)
		#		
		#			if ab_id != '00000000-0000-0000-0000-000000000000':
		#				bs.other_subscribe_ab(ab_id, ctc_head)
		#			
		#			for ctc_sess in backend.util_get_sessions_by_user(ctc_head):
		#				ctc_sess.evt.msn_on_notify_ab(cid_format(user_creator.uuid), str(util.misc.date_format(ctc_ab_last_modified or datetime.utcnow())))
		#	
		#	return render(req, 'msn:abservice/ManageWLConnection/ManageWLConnection.xml', {
		#		'cachekey': cachekey,
		#		'host': settings.LOGIN_HOST,
		#		'session_id': util.misc.gen_uuid(),
		#		'ab_id': ab_id,
		#		'contact': ctc_ab,
		#		'user_creator_detail': user_creator.detail,
		#	})
		#if action_str == 'FindFriendsInCommon':
		#	# Count the number of `Live` contacts from the target contact and compare then with the caller's contacts to see if both have the same contacts
		#	
		#	user = bs.user
		#	detail = user.detail
		#	assert detail is not None
		#	
		#	ctc_head = None
		#	matched_ab_ctcs = []
		#	
		#	ab_id = _find_element(action, 'ABId')
		#	if ab_id is not None:
		#		ab_id = str(ab_id)
		#	else:
		#		ab_id = '00000000-0000-0000-0000-000000000000'
		#	
		#	if ab_id not in detail.subscribed_ab_stores:
		#		return web.HTTPInternalServerError()
		#	
		#	try:
		#		domain_id = models.NetworkID(_find_element(action, 'domainID'))
		#	except ValueError:
		#		return web.HTTPInternalServerError()
		#	
		#	cid = str(_find_element(action, 'Cid'))
		#	
		#	tpl = backend.user_service.get_ab_contents(ab_id, user)
		#	assert tpl is not None
		#	_, _, _, _, ab_contacts = tpl
		#	
		#	for ab_contact in ab_contacts.values():
		#		if ab_contact.member_uuid is None: continue
		#		
		#		if cid_format(ab_contact.member_uuid) == cid and ab_contact.type == 'Live' and ab_contact.networkinfos.get(domain_id) is not None:
		#			ctc_head = backend._load_user_record(ab_contact.member_uuid)
		#	
		#	if ctc_head is None:
		#		return web.HTTPInternalServerError()
		#	
		#	tpl = backend.user_service.get_ab_contents(ab_id, ctc_head)
		#	assert tpl is not None
		#	_, _, _, _, ctc_ab_contacts = tpl
		#	
		#	for ctc_ab_ctc in ctc_ab_contacts:
		#		if ctc_ab_ctc.type != 'Live': continue
		#		
		#		for ab_ctc in ab_contacts:
		#			if ab_ctc.email == ctc_ab_ctc.email and ab_ctc.type == 'Live':
		#				matched_ab_ctcs.append(ab_ctc)
		#	
		#	#TODO: Response is a list of matched and unmatched `Contact`'s, but exactly what to add in the `Contact` nodes
		if action_str in { 'UpdateDynamicItem' }:
			# TODO: UpdateDynamicItem
			return _unknown_soap(req, header, action, expected = True)
	except Exception as ex:
		import traceback
		return render(req, 'msn:Fault.generic.xml', {
			'exception': traceback.format_exc(),
		})
	
	return _unknown_soap(req, header, action)

async def handle_storageservice(req: web.Request) -> web.Response:
	header, action, bs, token = await _preprocess_soap(req)
	assert bs is not None
	action_str = _get_tag_localname(action)
	now_str = util.misc.date_format(datetime.utcnow())
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
	
	user = bs.user
	
	backend = req.app['backend']
	
	if action_str == 'GetMetadata':
		return render(req, 'msn:oim/GetMetadataResponse.xml', {
			'md': gen_mail_data(user, backend, on_ns = False, e_node = False),
		})
	if action_str == 'GetMessage':
		oim_uuid = _find_element(action, 'messageId')
		oim_markAsRead = _find_element(action, 'alsoMarkAsRead')
		oim = backend.user_service.get_oim_single(user, oim_uuid, markAsRead = oim_markAsRead is True)
		return render(req, 'msn:oim/GetMessageResponse.xml', {
			'oim_data': format_oim(oim),
		})
	if action_str == 'DeleteMessages':
		messageIds = action.findall('.//{*}messageIds/{*}messageId')
		if not messageIds:
			return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			if backend.user_service.get_oim_single(user, messageId) is None:
				return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			backend.user_service.delete_oim(user.uuid, messageId)
		bs.evt.msn_on_oim_deletion(len(messageIds))
		return render(req, 'msn:oim/DeleteMessagesResponse.xml')
	
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

async def handle_oim(req: web.Request) -> web.Response:
	header, body_msgtype, body_content, bs, token = await _preprocess_soap_oimws(req)
	soapaction = req.headers.get('SOAPAction').strip('"')
	
	lockkey_result = header.find('.//{*}Ticket').get('lockkey')
	
	if bs is None or lockkey_result in (None,''):
		return render(req, 'msn:oim/Fault.authfailed.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	backend: Backend = req.app['backend']
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	friendlyname = None
	friendlyname_str = None
	friendly_charset = None
	
	friendlyname_mime = header.find('.//{*}From').get('friendlyName')
	email = header.find('.//{*}From').get('memberName')
	recipient = header.find('.//{*}To').get('memberName')
	
	recipient_uuid = backend.util_get_uuid_from_email(recipient)
	
	if email != user.email or recipient_uuid is None or not _is_on_al(recipient_uuid, backend, user, detail):
		return render(req, 'msn:oim/Fault.unavailable.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	assert req.transport is not None
	peername = req.transport.get_extra_info('peername')
	if peername:
		host = peername[0]
	else:
		host = '127.0.0.1'
	
	oim_msg_seq = str(_find_element(header, 'Sequence/MessageNumber'))
	if not oim_msg_seq.isnumeric():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	if friendlyname_mime is not None:
		try:
			friendlyname, friendly_charset = decode_header(friendlyname_mime)[0]
		except:
			return render(req, 'msn:oim/Fault.invalidcontent.xml', {
				'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
			}, status = 500)
	
	if friendly_charset is None:
		friendly_charset = 'utf-8'
	
	if friendlyname is not None:
		friendlyname_str = friendlyname.decode(friendly_charset)
	
	oim_proxy_string = header.find('.//{*}From').get('proxy')
	
	try:
		oim_mime = Parser().parsestr(body_content)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	oim_run_id = str(oim_mime.get('X-OIM-Run-Id'))
	if oim_run_id is None:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if not re.match(r'^\{?[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}\}?', oim_run_id):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_run_id = oim_run_id.replace('{', '').replace('}', '')
	if ('X-Message-Info','Received','From','To','Subject','X-OIM-originatingSource','X-OIMProxy','Message-ID','X-OriginalArrivalTime','Date','Return-Path') in oim_mime.keys():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('MIME-Version')) != '1.0':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if not str(oim_mime.get('Content-Type')).startswith('text/plain'):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('Content-Transfer-Encoding')) != 'base64':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('X-OIM-Message-Type')) != 'OfflineMessage':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_seq_num = str(oim_mime.get('X-OIM-Sequence-Num'))
	if oim_seq_num != oim_msg_seq:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_headers = {name: str(value) for name, value in oim_mime.items()}
	
	try:
		i = body_content.index('\n\n') + 2
		oim_body = body_content[i:]
		for oim_b64_line in oim_body.split('\n'):
			if len(oim_b64_line) > 77:
				return render(req, 'msn:oim/Fault.invalidcontent.xml', {
					'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
				}, status = 500)
		oim_body_normal = oim_body.strip()
		oim_body_normal = base64.b64decode(oim_body_normal).decode('utf-8')
		
		backend.user_service.save_oim(bs, recipient_uuid, oim_run_id, host, oim_body_normal, True, from_friendly = friendlyname_str, from_friendly_charset = friendly_charset, headers = oim_headers, oim_proxy = oim_proxy_string)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	return render(req, 'msn:oim/StoreResponse.xml', {
		'seq': oim_msg_seq,
		'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
	})

def _is_on_al(uuid: str, backend: Backend, user: models.User, detail: models.UserDetail) -> bool:
	contact = detail.contacts.get(uuid)
	if user.settings.get('BLP', 'AL') == 'AL' and (contact is None or not contact.lists & models.Lst.BL):
		return True
	if user.settings.get('BLP', 'AL') == 'BL' and contact is not None and not contact.lists & models.Lst.BL:
		return True
	
	if contact is not None:
		ctc_detail = backend._load_detail(contact.head)
		assert ctc_detail is not None
		
		ctc_me = ctc_detail.contacts.get(user.uuid)
		if ctc_me is None and contact.head.settings.get('BLP', 'AL') == 'AL':
			return True
		if ctc_me is not None and not ctc_me.lists & models.Lst.BL:
			return True
	return False

def _unknown_soap(req: web.Request, header: Any, action: Any, *, expected: bool = False) -> web.Response:
	action_str = _get_tag_localname(action)
	if not expected and settings.DEBUG:
		print("Unknown SOAP:", action_str)
		print(_xml_to_string(header))
		print(_xml_to_string(action))
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

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
	token = token_tag.text
	if token is not None:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = _find_element(root, 'Header')
	action = _find_element(root, 'Body/*[1]')
	if settings.DEBUG and settings.DEBUG_MSNP: print('Action: {}'.format(_get_tag_localname(action)))
	
	return header, action, bs, token

async def _preprocess_soap_oimws(req: web.Request) -> Tuple[Any, str, str, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token = root.find('.//{*}Ticket').get('passport')
	if token[0:2] == 't=':
		token = token[2:22]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = _find_element(root, 'Header')
	body_msgtype = str(_find_element(root, 'Body/MessageType'))
	body_content = str(_find_element(root, 'Body/Content')).replace('\r\n', '\n')
	
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
		body = await req.read() # type: Optional[bytes]
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
			result = envelope.format(MsgrConfig = config.format(targethost = settings.TARGET_HOST, tabs = config_tabs))
		elif 8 <= int(config_ver[0]) <= 9:
			with open(TMPL_DIR + '/MsgrConfig.wlm.8.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = config.format(targethost = settings.TARGET_HOST, tabs = config_tabs)
		elif int(config_ver[0]) >= 14:
			with open(TMPL_DIR + '/MsgrConfig.wlm.14.xml') as fh:
				config = fh.read()
			# TODO: Tabs in WLM 2009+
			#with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			#	config_tabs = fh.read()
			result = config.format(targethost = settings.TARGET_HOST)
	elif body is not None:
		with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
			envelope = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
			config = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			config_tabs = fh.read()
		result = envelope.format(MsgrConfig = config.format(targethost = settings.TARGET_HOST, tabs = config_tabs))
	
	return result or ''

PassportURLs = 'PassportURLs'
if settings.DEBUG:
	# Caddy (on the live server) standardizes all header names, and so
	# turns this into 'Passporturls'. Because of this, patching MSN
	# involves changing that string in the executable as well.
	# But then if you try to use a patched MSN with a dev server, it
	# won't work, so we have to standardize the header name here.
	PassportURLs = PassportURLs.title()

async def handle_nexus(req: web.Request) -> web.Response:
	return web.HTTPOk(headers = {
		PassportURLs: 'DALogin=https://{}{}'.format(settings.LOGIN_HOST, LOGIN_PATH),
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
	
	token = _login(req, email, pwd, binary_secret = True, lifetime = 86400)
	
	uuid = backend.util_get_uuid_from_email(email)
	
	if token is not None and uuid is not None:
		day_before_expiry = datetime.utcfromtimestamp((backend.auth_service.get_token_expiry('nb/login', token) or 0) - 86400)
		timez = util.misc.date_format(day_before_expiry)
		tomorrowz = util.misc.date_format((day_before_expiry + timedelta(days = 1)))
		time_5mz = util.misc.date_format((day_before_expiry + timedelta(minutes = 5)))
		
		# load PUID and CID, assume them to be the same for our purposes
		cid = cid_format(uuid)
		
		assert req.transport is not None
		peername = req.transport.get_extra_info('peername')
		if peername:
			host = peername[0]
		else:
			host = '127.0.0.1'
		
		# get list of requested domains
		domains = root.findall('.//{*}Address')
		domains.remove('http://Passport.NET/tb') # ignore Passport token request
		
		tpl = backend.auth_service.get_token('nb/login', token) # type: Optional[Tuple[str, Optional[str]]]
		assert tpl is not None
		_, bsecret = tpl
		
		tmpl = req.app['jinja_env'].get_template(('msn:RST/RST2.token.xml' if rst2 else 'msn:RST/RST.token.xml'))
		# collect tokens for requested domains
		tokenxmls = [tmpl.render(
			i = i + 1,
			domain = domain,
			timez = timez,
			tomorrowz = tomorrowz,
			pptoken1 = token,
			binarysecret = bsecret,
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
		'timez': util.misc.date_format(datetime.utcnow()),
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
	content = tmpl.render(**(ctxt or {}))
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

def _login(req: web.Request, email: str, pwd: str, binary_secret: bool = False, lifetime: int = 30) -> Optional[str]:
	backend: Backend = req.app['backend']
	bsecret = None
	uuid = backend.user_service.login(email, pwd)
	if uuid is None: return None
	return backend.auth_service.create_token('nb/login', (uuid, base64.b64encode(secrets.token_bytes(24)).decode('ascii') if binary_secret else None), lifetime = lifetime)

def _bool_to_str(b: bool) -> str:
	return 'true' if b else 'false'

def _contact_is_favorite(groups: Dict[str, models.Group], ctc: models.ABContact) -> bool:
	for group_id in ctc.groups:
		if group_id not in groups: continue
		if groups[group_id].is_favorite: return True
	return False

_CONTACT_PROPERTIES = (
	'Comment', 'DisplayName', 'ContactType', 'ContactFirstName', 'ContactLastName', 'MiddleName', 'Anniversary', 'ContactBirthDate', 'ContactEmail', 'ContactLocation', 'ContactWebSite', 'ContactPrimaryEmailType', 'ContactPhone', 'GroupName',
	'IsMessengerEnabled', 'IsMessengerUser', 'IsFavorite', 'HasSpace',
	'Annotation', 'Capability', 'MessengerMemberInfo',
)

_CONTACT_PHONE_PROPERTIES = (
	'Number',
)

_CONTACT_EMAIL_PROPERTIES = (
	'Email',
)

_CONTACT_LOCATION_PROPERTIES = (
	'Name', 'Street', 'City', 'State', 'Country', 'PostalCode',
)

_ANNOTATION_NAMES = (
	'MSN.IM.InviteMessage', 'MSN.IM.MPOP', 'MSN.IM.BLP', 'MSN.IM.GTC', 'MSN.IM.RoamLiveProperties',
	'MSN.IM.MBEA', 'MSN.IM.BuddyType', 'AB.NickName', 'AB.Profession', 'AB.Spouse', 'AB.JobTitle', 'Live.Locale', 'Live.Profile.Expression.LastChanged',
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
