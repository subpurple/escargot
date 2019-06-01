from typing import Optional, Any, Dict, Tuple
from datetime import datetime, timedelta
from enum import IntEnum
from email.parser import Parser
from email.header import decode_header
from urllib.parse import unquote
from pathlib import Path
import lxml
import re
import asyncio
import secrets
import base64
import json
import time
from dateutil import parser as iso_parser
from markupsafe import Markup
from aiohttp import web

import settings
from core import models, event, error
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
from .misc import gen_mail_data, format_oim, cid_format, gen_signedticket_xml
from .msnp_ns import GroupChatEventHandler
import util.misc

LOGIN_PATH = '/login'
TMPL_DIR = 'front/msn/tmpl'
ETC_DIR = 'front/msn/etc'
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
	app.router.add_get('/etc/text-ad-service', handle_textad)
	
	# MSN >= 7.5
	app.router.add_route('OPTIONS', '/NotRST.srf', handle_not_rst)
	app.router.add_post('/NotRST.srf', handle_not_rst)
	app.router.add_post('/RST.srf', handle_rst)
	app.router.add_post('/RST2.srf', lambda req: handle_rst(req, rst2 = True))
	
	# MSN 8.1.0178
	# TODO: Use SOAP library for SOAP services.
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
				'Lst': models.Lst,
				'lists': [models.Lst.AL, models.Lst.BL],
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
						
						if lst == models.Lst.RL:
							bs.me_contact_add(contact_uuid, models.Lst.AL)
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
			
			contact_uuid = None
			
			memberships = action.findall('.//{*}memberships/{*}Membership')
			for membership in memberships:
				lst = models.Lst.Parse(str(_find_element(membership, 'MemberRole')))
				assert lst is not None
				members = membership.findall('.//{*}Members/{*}Member')
				for member in members:
					member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
					if member_type == 'PassportMember':
						if _find_element(member, 'Type') == 'Passport' and _find_element(member, 'State') == 'Accepted':
							try:
								contact_uuid = _find_element(member, 'MembershipId').split('/', 1)[1]
							except:
								email = _find_element(member, 'PassportName')
								contact_uuid = backend.util_get_uuid_from_email(email or '')
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			return render(req, 'msn:abservice/ABFindAllResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'Lst': models.Lst,
				'user': user,
				'detail': user.detail,
				'now': now_str,
				'ab_id': ab_id,
			})
		if action_str == 'ABFindContactsPaged':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			groupchat = None
			
			ab_id = _find_element(action, 'ABId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			try:
				if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
					return web.HTTPInternalServerError()
			except:
				return web.HTTPInternalServerError()
			
			if ab_id == '00000000-0000-0000-0000-000000000000':
				ab_type = 'Individual'
			else:
				ab_type = 'Group'
				chat_id = ab_id[-12:]
				groupchat = backend.user_service.get_groupchat(chat_id)
			
			groupchats = [groupchat for groupchat in backend.user_service.get_groupchat_batch(user) if not (groupchat.memberships[user.uuid].role == models.GroupChatRole.Empty or groupchat.memberships[user.uuid].state == models.GroupChatState.Empty)]
			
			return render(req, 'msn:abservice/ABFindContactsPagedResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'Lst': models.Lst,
				'user': user,
				'detail': user.detail,
				'now': now_str,
				'groupchats': groupchats,
				'groupchat': groupchat,
				'GroupChatRole': models.GroupChatRole,
				'GroupChatState': models.GroupChatState,
				'signedticket': Markup(gen_signedticket_xml(bs, backend).replace('<', '&lt;').replace('>', '&gt;')),
				'ab_id': ab_id,
				'ab_type': ab_type,
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
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
			
			annotations = contact.findall('.//{*}annotations/{*}Annotation')
			annotations_dict = {} # type: Dict[str, Any]
			if annotations:
				for annotation in annotations:
					name = _find_element(annotation, 'Name')
					if name not in _ANNOTATION_NAMES:
						return web.HTTPInternalServerError()
					value = _find_element(annotation, 'Value')
					if name is 'AB.NickName':
						nickname = value
			
			add_ctc = False
			
			ctc = detail.contacts.get(contact_uuid)
			if ctc is not None:
				if not ctc.lists & models.Lst.FL:
					add_ctc = True
			else:
				add_ctc = True
			
			if add_ctc:
				try:
					bs.me_contact_add(contact_uuid, models.Lst.FL, name = email, nickname = nickname)
				except:
					pass
			
			return render(req, 'msn:abservice/ABContactAddResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'contact_uuid': contact_uuid,
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			contacts = action.findall('.//{*}contacts/{*}Contact')
			for contact in contacts:
				contact_uuid = _find_element(contact, 'contactId')
				assert contact_uuid is not None
				try:
					bs.me_contact_remove(contact_uuid, models.Lst.FL)
				except:
					pass
			return render(req, 'msn:abservice/ABContactDeleteResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'ABContactUpdate':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'abId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			contacts = action.findall('.//{*}contacts/{*}Contact')
			for contact in contacts:
				ctc = None
				contact_info = _find_element(contact, 'contactInfo')
				if _find_element(contact_info, 'contactType') == 'Me':
					contact_uuid = user.uuid
				else:
					contact_uuid = _find_element(contact, 'contactId')
				if not contact_uuid:
					return web.HTTPInternalServerError()
				if contact_uuid is not user.uuid:
					ctc = detail.contacts.get(contact_uuid)
					if not ctc:
						return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
							'action_str': 'ABContactUpdate',
						}, status = 500)
				properties_changed = contact.find('./{*}propertiesChanged')
				if not properties_changed:
					return web.HTTPInternalServerError()
				properties_changed = str(properties_changed).strip().split(' ')
				for contact_property in properties_changed:
					if contact_property not in _CONTACT_PROPERTIES:
						return web.HTTPInternalServerError()
				
				for contact_property in properties_changed:
					if contact_property == 'Anniversary':
						assert ctc is not None
						property = _find_element(contact_info, 'Anniversary')
						# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
						try:
							if property not in (None,-1):
								property = str(property)
								property = datetime.strptime(property, '%Y/%m/%d')
						except:
							return web.HTTPInternalServerError()
					if contact_property == 'ContactBirthDate':
						assert ctc is not None
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
						assert ctc is not None
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
						assert ctc is not None
						property = _find_element(contact_info, 'isMessengerUser')
						if property is None:
							return web.HTTPInternalServerError()
					if contact_property == 'ContactEmail':
						assert ctc is not None
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
						assert ctc is not None
						email_primary_type = str(_find_element(contact_info, 'primaryEmailType'))
						if email_primary_type not in ('Passport','ContactEmailPersonal','ContactEmailBusiness','ContactEmailOther'):
							return web.HTTPInternalServerError()
					if contact_property == 'ContactPhone':
						assert ctc is not None
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
						assert ctc is not None
						contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
						for contact_website in contact_websites:
							if str(_find_element(contact_website, 'contactWebSiteType')) not in ('ContactWebSitePersonal','ContactWebSiteBusiness'):
								return web.HTTPInternalServerError()
					if contact_property == 'Annotation':
						if _find_element(contact_info, 'contactType') != 'Me':
							if ctc is None:
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
					if ctc is None:
						return web.HTTPInternalServerError()
			for contact in contacts:
				updated = False
				ctc = None
				contact_info = _find_element(contact, 'contactInfo')
				if _find_element(contact_info, 'contactType') == 'Me':
					contact_uuid = user.uuid
				else:
					contact_uuid = _find_element(contact, 'contactId')
				if contact_uuid is not user.uuid and contact_uuid is not None:
					ctc = detail.contacts.get(contact_uuid)
				properties_changed = str(contact.find('./{*}propertiesChanged')).strip().split(' ')
				
				for contact_property in properties_changed:
					if contact_property == 'ContactFirstName':
						assert ctc is not None
						property = _find_element(contact_info, 'firstName')
						ctc.detail.first_name = property
						updated = True
					if contact_property == 'ContactLastName':
						assert ctc is not None
						property = _find_element(contact_info, 'lastName')
						ctc.detail.last_name = property
						updated = True
					if contact_property == 'MiddleName':
						assert ctc is not None
						property = _find_element(contact_info, 'MiddleName')
						ctc.detail.middle_name = property
						updated = True
					if contact_property == 'Anniversary':
						assert ctc is not None
						property = _find_element(contact_info, 'Anniversary')
						# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
						if property not in (None,-1):
							property = str(property)
							property = datetime.strptime(property, '%Y/%m/%d')
						if property is -1:
							property = None
						ctc.detail.anniversary = property
						updated = True
					if contact_property == 'ContactBirthDate':
						assert ctc is not None
						property = _find_element(contact_info, 'birthdate')
						if property is not None:
							property = str(property)
							if property != '0001-01-01T00:00:00':
								property = iso_parser.parse(property)
							else:
								property = None
						ctc.detail.birthdate = property
						updated = True
					if contact_property == 'Comment':
						assert ctc is not None
						property = _find_element(contact_info, 'comment')
						if property is not None:
							property = str(property)
						ctc.detail.notes = property
						updated = True
					if contact_property == 'ContactLocation':
						assert ctc is not None
						contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
						for contact_location in contact_locations:
							contact_location_type = str(_find_element(contact_location, 'contactLocationType'))
							location_properties_changed = str(_find_element(contact_location, 'Changes')).strip().split(' ')
							if contact_location_type not in ctc.detail.locations:
								ctc.detail.locations[contact_location_type] = models.ContactLocation(contact_location_type)
							for location_property in location_properties_changed:
								if location_property == 'Name':
									property = _find_element(contact_location, 'name')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].name = property
									updated = True
								if location_property == 'Street':
									property = _find_element(contact_location, 'street')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].street = property
									updated = True
								if location_property == 'City':
									property = _find_element(contact_location, 'city')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].city = property
									updated = True
								if location_property == 'State':
									property = _find_element(contact_location, 'state')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].state = property
									updated = True
								if location_property == 'Country':
									property = _find_element(contact_location, 'country')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].country = property
									updated = True
								if location_property == 'PostalCode':
									property = _find_element(contact_location, 'postalCode')
									if property is not None:
										property = str(property)
									ctc.detail.locations[contact_location_type].zip_code = property
									updated = True
							if ctc.detail.locations[contact_location_type].street is None and ctc.detail.locations[contact_location_type].city is None and ctc.detail.locations[contact_location_type].state is None and ctc.detail.locations[contact_location_type].country is None and ctc.detail.locations[contact_location_type].zip_code is None:
								del ctc.detail.locations[contact_location_type]
								updated = True
					if contact_property == 'IsMessengerUser':
						assert ctc is not None
						property = _find_element(contact_info, 'isMessengerUser')
						ctc.is_messenger_user = property
						updated = True
					if contact_property == 'ContactEmail':
						assert ctc is not None
						contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
						for contact_email in contact_emails:
							email_properties_changed = str(_find_element(contact_email, 'propertiesChanged')).strip().split(' ')
							for email_property in email_properties_changed:
								if email_property == 'Email':
									email = contact_email.find('./{*}email')
									if email is not None:
										email = str(email)
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailPersonal':
										ctc.detail.personal_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailBusiness':
										ctc.detail.work_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailMessenger':
										ctc.detail.im_email = email
									if _find_element(contact_email, 'contactEmailType') == 'ContactEmailOther':
										ctc.detail.other_email = email
									updated = True
					if contact_property == 'ContactPrimaryEmailType':
						assert ctc is not None
						email_primary_type = str(_find_element(contact_info, 'primaryEmailType'))
						ctc.detail.primary_email_type = email_primary_type
						updated = True
					if contact_property == 'ContactPhone':
						assert ctc is not None
						contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
						for contact_phone in contact_phones:
							phone_properties_changed = str(_find_element(contact_phone, 'propertiesChanged')).strip().split(' ')
							for phone_property in phone_properties_changed:
								if phone_property == 'Number':
									phone_number = contact_phone.find('./{*}number')
									if phone_number is not None:
										phone_number = str(phone_number)
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePersonal':
										ctc.detail.home_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneBusiness':
										ctc.detail.work_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneFax':
										ctc.detail.fax_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePager':
										ctc.detail.pager_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneMobile':
										ctc.detail.mobile_phone = phone_number
									if _find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneOther':
										ctc.detail.other_phone = phone_number
									updated = True
					if contact_property == 'ContactWebSite':
						assert ctc is not None
						contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
						for contact_website in contact_websites:
							contact_website_type = str(_find_element(contact_website, 'contactWebSiteType'))
							website = str(_find_element(contact_website, 'webURL'))
							if contact_website_type == 'ContactWebSitePersonal':
								ctc.detail.personal_website = website
							if contact_website_type == 'ContactWebSiteBusiness':
								ctc.detail.business_website = website
							updated = True
					if contact_property == 'Annotation':
						if contact_uuid is not None:
							if _find_element(contact_info, 'contactType') != 'Me' and not ctc:
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
								if ctc:
									ctc.detail.nickname = value
									updated = True
								continue
							if name == 'Live.Profile.Expression.LastChanged':
								# TODO: What's this used for?
								continue
				if updated:
					backend._mark_modified(user)
			
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
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
				contact_uuid = backend.util_get_uuid_from_email(email)
				assert contact_uuid is not None
				
				ctc = detail.contacts.get(contact_uuid)
				if ctc is not None and ctc.lists & models.Lst.FL:
					for group_id in group_ids:
						for group_contact_entry in ctc._groups:
							if group_contact_entry.uuid == group_id:
								return web.HTTPInternalServerError()
				
				for group_id in group_ids:
					try:
						ctc, _ = bs.me_contact_add(contact_uuid, models.Lst.FL, group_id = group_id, name = email)
					except:
						return web.HTTPInternalServerError()
			else:
				contact_uuid = _find_element(action, 'contactId')
				assert contact_uuid is not None
				
				ctc = detail.contacts.get(contact_uuid)
				if ctc is None or not ctc.lists & models.Lst.FL:
					return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
						'action_str': 'ABGroupContactAdd',
					}, status = 500)
				else:
					for group_id in group_ids:
						for group_contact_entry in ctc._groups:
							if group_contact_entry.uuid == group_id:
								return web.HTTPInternalServerError()
				
				for group_id in group_ids:
					bs.me_group_contact_add(group_id, ctc.head.uuid)
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
			
			if ab_id != '00000000-0000-0000-0000-000000000000':
				return web.HTTPInternalServerError()
			
			group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
			
			for group_id in group_ids:
				if group_id not in detail._groups_by_uuid:
					return web.HTTPInternalServerError()
			
			contact_uuid = _find_element(action, 'contactId')
			ctc = detail.contacts.get(contact_uuid or '')
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
			else:
				return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
					'action_str': 'ABGroupContactDelete',
				}, status = 500)
			return render(req, 'msn:abservice/ABGroupContactDeleteResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
			})
		if action_str == 'CreateCircle':
			user = bs.user
			
			if _find_element(action, 'Domain') == 1 and _find_element(action, 'HostedDomain') == 'live.com' and _find_element(action, 'Type') == 2 and isinstance(_find_element(action, 'IsPresenceEnabled'), bool):
				membership_access = int(_find_element(action, 'MembershipAccess'))
				#request_membership_option = int(_find_element(action, 'RequestMembershipOption'))
				
				name = str(_find_element(action, 'DisplayName'))
				owner_friendly = str(_find_element(action, 'PublicDisplayName'))
				
				chat_id = bs.me_create_groupchat(name, owner_friendly, membership_access)
				
				try:
					return render(req, 'msn:sharing/CreateCircleResponse.xml', {
						'cachekey': cachekey,
						'host': settings.LOGIN_HOST,
						'session_id': util.misc.gen_uuid(),
						'chat_id': chat_id,
					})
				finally:
					backend.loop.create_task(join_creator_to_groupchat(backend, user, chat_id))
		if action_str == 'CreateContact':
			# Used as a step in Circle invites, but also used for regular contact adds in WLM 2011/2012
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'ABId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if not (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12):
				return web.HTTPInternalServerError()
			
			chat_id = ab_id[-12:]
			contact_email = _find_element(action, 'Email')
			
			contact_uuid = backend.util_get_uuid_from_email(contact_email)
			if contact_uuid is None:
				return web.HTTPInternalServerError()
			head = backend._load_user_record(contact_uuid)
			if head is None: return web.HTTPInternalServerError()
			
			groupchat = backend.user_service.get_groupchat(chat_id)
			
			if groupchat is None:
				return web.HTTPInternalServerError()
			
			try:
				bs.me_add_user_to_groupchat(groupchat, head)
			except error.MemberAlreadyInGroupChat:
				return render(req, 'msn:abservice/Fault.contactalreadyexists.xml', {
					'action_str': 'CreateContact',
				}, status = 500)
			except:
				return web.HTTPInternalServerError()
			
			return render(req, 'msn:abservice/CreateContactResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'ab_id': ab_id,
				'head': head,
				'now': now_str,
			})
		if action_str == 'ManageWLConnection':
			user = bs.user
			detail = user.detail
			assert detail is not None
			
			ab_id = _find_element(action, 'ABId')
			if ab_id is not None:
				ab_id = str(ab_id)
			else:
				ab_id = '00000000-0000-0000-0000-000000000000'
			
			if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
				print('ab id incorrect')
				return web.HTTPInternalServerError()
			
			groupchat = None
			invite_message = None
			circle_mode = False
			
			contact_uuid = _find_element(action, 'contactId')
			assert contact_uuid is not None
			if ab_id != '00000000-0000-0000-0000-000000000000':
				head = backend._load_user_record(contact_uuid)
			else:
				head = user
			
			if head is None:
				return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
					'action_str': 'ManageWLConnection',
				}, status = 500)
			
			if ab_id == '00000000-0000-0000-0000-000000000000' and contact_uuid.startswith('00000000-0000-0000-0009-'):
				chat_id = contact_uuid[-12:]
				uuid = head.uuid
				circle_mode = True
			elif ab_id.startswith('00000000-0000-0000-0009-'):
				chat_id = ab_id[-12:]
				uuid = contact_uuid
				circle_mode = True
			
			if circle_mode:
				groupchat = backend.user_service.get_groupchat(chat_id)
				if groupchat is None or uuid not in groupchat.memberships:
					print('groupchat is None or user not in chat')
					return web.HTTPInternalServerError()
			
			if _find_element(action, 'connection') == True:
				try:
					relationship_type = models.RelationshipType(_find_element(action, 'relationshipType'))
					relationship_role = int(_find_element(action, 'relationshipRole'))
					wl_action = int(_find_element(action, 'action'))
				except ValueError:
					return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
						'cachekey': cachekey,
						'host': settings.LOGIN_HOST,
						'session_id': util.misc.gen_uuid(),
						'error': 'Relationship variables invalid',
					}, status = 500)
				
				if relationship_type == models.RelationshipType.Circle:
					if wl_action == 1:
						if groupchat is None:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.LOGIN_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': 'Relationship type not suitable for non-specialized contacts',
							}, status = 500)
						if relationship_role == 0:
							if ab_id == '00000000-0000-0000-0000-000000000000':
								membership = groupchat.memberships[head.uuid]
								if not (membership.role == models.GroupChatRole.StatePendingOutbound and membership.state == models.GroupChatState.WaitingResponse):
									return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
										'cachekey': cachekey,
										'host': settings.LOGIN_HOST,
										'session_id': util.misc.gen_uuid(),
										'error': 'User `{email}` already accepted in `GroupChat`'.format(email = head.email),
									})
								try:
									bs.me_change_groupchat_membership(groupchat, head, role = models.GroupChatRole.Member, state = models.GroupChatState.Accepted, bs = bs)
								except error.MemberNotInGroupChat:
									return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
										'cachekey': cachekey,
										'host': settings.LOGIN_HOST,
										'session_id': util.misc.gen_uuid(),
										'error': 'User `{email}` does not have membership in `GroupChat`'.format(email = head.email),
									}, status = 500)
								except error.GroupChatDoesNotExist:
									return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
										'cachekey': cachekey,
										'host': settings.LOGIN_HOST,
										'session_id': util.misc.gen_uuid(),
										'error': '`GroupChat` does not currently exist',
									}, status = 500)
						elif relationship_role == 3:
							annotations = action.findall('.//{*}annotations/{*}Annotation')
							for annotation in annotations:
								name = _find_element(annotation, 'Name')
								value = _find_element(annotation, 'Value')
								
								if name == 'MSN.IM.InviteMessage':
									invite_message = value
									break
							try:
								bs.me_invite_user_to_groupchat(groupchat, head, invite_message = invite_message)
							except error.MemberNotInGroupChat:
								return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
									'cachekey': cachekey,
									'host': settings.LOGIN_HOST,
									'session_id': util.misc.gen_uuid(),
									'error': 'User `{email}` does not have initialized membership in `GroupChat`'.format(email = head.email),
								}, status = 500)
							except error.MemberAlreadyInvitedToGroupChat:
								return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
									'cachekey': cachekey,
									'host': settings.LOGIN_HOST,
									'session_id': util.misc.gen_uuid(),
									'error': 'User `{email}` already invited to `GroupChat`'.format(email = head.email),
								}, status = 500)
							except error.GroupChatDoesNotExist:
								return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
									'cachekey': cachekey,
									'host': settings.LOGIN_HOST,
									'session_id': util.misc.gen_uuid(),
									'error': '`GroupChat` does not currently exist',
								}, status = 500)
						else:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.LOGIN_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': 'RelationshipRole `{role}` not currently supported for relationship type `{type}`'.format(role = relationship_role, type = relationship_type.name),
							}, status = 500)
					else:
						print('no other actions supported')
						return web.HTTPInternalServerError()
			else:
				return web.HTTPInternalServerError()
			
			return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'ab_id': ab_id,
				'head': head,
				'groupchat': groupchat,
				'GroupChatRole': models.GroupChatRole,
				'GroupChatState': models.GroupChatState,
				'now': now_str,
			})
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
		#	tpl = backend.user_service.get_ab_contents(user)
		#	assert tpl is not None
		#	_, _, _, ab_contacts = tpl
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
		#	tpl = backend.user_service.get_ab_contents(ctc_head)
		#	assert tpl is not None
		#	_, _, _, ctc_ab_contacts = tpl
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
		oim = backend.user_service.get_oim_single(user, oim_uuid, mark_read = oim_markAsRead is True)
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

async def handle_textad(req: web.Request) -> web.Response:
	with open(ETC_DIR + '/textads.json') as f:
		textads = json.loads(f.read())
		f.close()
	
	if len(textads) == 0: return web.HTTPOk()
	
	if len(textads) > 1:
		ad = textads[secrets.randbelow((len(textads)-1))]
	else:
		ad = textads[0]
	return render(req, 'msn:textad.xml', {
		'caption': ad['caption'],
		'hiturl': ad['hiturl'],
	})

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
			result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
		elif 8 <= int(config_ver[0]) <= 9:
			with open(TMPL_DIR + '/MsgrConfig.wlm.8.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = config.format(tabs = config_tabs)
		elif int(config_ver[0]) >= 14:
			with open(TMPL_DIR + '/MsgrConfig.wlm.14.xml') as fh:
				config = fh.read()
			# TODO: Tabs in WLM 2009+
			#with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			#	config_tabs = fh.read()
			result = config.format()
	elif body is not None:
		with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
			envelope = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
			config = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			config_tabs = fh.read()
		result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
	
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

def _get_storage_path(uuid: str) -> Path:
	return Path('storage/dp') / uuid[0:1] / uuid[0:2]

async def join_creator_to_groupchat(backend: Backend, user: models.User, chat_id: str) -> None:
	for sess in backend.util_get_sessions_by_user(user):
		await asyncio.sleep(0.2)
		sess.evt.msn_on_notify_ab()
		await asyncio.sleep(0.2)
		sess.evt.on_groupchat_created(chat_id)

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
		path.mkdir(parents = True, exist_ok = True)
		
		image_path = path / '{uuid}.{mime}'.format(uuid = user.uuid, mime = mime)
		
		image_path.write_bytes(data)
		
		image = Image.open(image_path)
		thumb = image.resize((21, 21))
		
		thumb_path = path / '{uuid}_thumb.{mime}'.format(uuid = user.uuid, mime = mime)
		thumb.save(str(thumb_path))
	
	return render(req, 'msn:storageservice/CreateDocumentResponse.xml', {
		'user': user,
		'cid': cid,
		'pptoken1': token,
		'timestamp': timestamp,
	})

async def handle_usertile(req: web.Request, small: bool = False) -> web.Response:
	uuid = req.match_info['uuid']
	storage_path = _get_storage_path(uuid)
	files = list(storage_path.iterdir())
	
	if not files:
		raise web.HTTPNotFound()
	
	ext = files[0].suffix
	image_path = storage_path / '{}{}{}'.format(uuid, '_thumb' if small else '', ext)
	return web.HTTPOk(content_type = 'image/{}'.format(ext), body = image_path.read_bytes())

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

def _contact_is_favorite(user_detail: models.UserDetail, ctc: models.Contact) -> bool:
	groups = user_detail._groups_by_uuid
	for group in ctc._groups.copy():
		if group.id not in groups: continue
		if groups[group.id].is_favorite: return True
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
