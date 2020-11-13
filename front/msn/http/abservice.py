from typing import Any, Tuple, List, Optional, Tuple
from enum import IntEnum
from datetime import datetime
import asyncio
import secrets
import sys

from aiohttp import web
from dateutil import parser as iso_parser
from markupsafe import Markup

from core import models, error
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
import util.misc
import settings

from .util import preprocess_soap, get_tag_localname, unknown_soap, find_element, render, bool_to_str
from ..misc import gen_signedticket_xml

def register(app: web.Application) -> None:
	app.router.add_post('/abservice/SharingService.asmx', lambda req: handle_abservice(req, sharing = True))
	app.router.add_post('/abservice/abservice.asmx', handle_abservice)

async def handle_abservice(req: web.Request, *, sharing: bool = False) -> web.Response:
	header, action, bs, _ = await preprocess_soap(req)
	if bs is None:
		raise web.HTTPForbidden()
	action_str = get_tag_localname(action)
	if find_element(action, 'deltasOnly') or find_element(action, 'DeltasOnly'):
		return render(req, 'msn:abservice/Fault.fullsync.xml', { 'faultactor': action_str })
	
	#print(_xml_to_string(action))
	
	method = getattr(sys.modules[__name__], ('sharing' if sharing else 'ab') + '_' + action_str, None)
	if not method:
		return unknown_soap(req, header, action)
	
	try:
		return method(req, header, action, bs)
	except:
		import traceback
		return render(req, 'msn:Fault.generic.xml', {
			'exception': traceback.format_exc(),
		}, status = 500)

def sharing_FindMembership(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	user = bs.user
	detail = user.detail
	cachekey = secrets.token_urlsafe(172)
	return render(req, 'msn:sharing/FindMembershipResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'user': user,
		'detail': detail,
		'Lst': models.Lst,
		'lists': [models.Lst.AL, models.Lst.BL, models.Lst.RL],
		'groupchats': backend.user_service.get_groupchat_batch(user),
		'now': now_str,
	})

def sharing_AddMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		email = None # type: Optional[str]
		circle_id = None
		
		lst = models.Lst.Parse(str(find_element(membership, 'MemberRole')))
		assert lst is not None
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'PassportName')
			elif member_type == 'EmailMember':
				if find_element(member, 'Type') == 'Email' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'Email')
			elif member_type == 'CircleMember':
				if find_element(member, 'Type') == 'Circle' and find_element(member, 'State') == 'Accepted':
					circle_id = find_element(member, 'CircleId')
			if email is None and circle_id is None:
				return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
			if email is not None:
				name = None
				contact_uuid = backend.util_get_uuid_from_email(email)
				if contact_uuid is None:
					return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
				ctc = detail.contacts.get(contact_uuid)
				if ctc is None:
					name = email
				
				try:
					bs.me_contact_add(contact_uuid, lst, name = name)
				except error.ListIsFull:
					return web.HTTPInternalServerError()
				except:
					pass
			elif circle_id is not None:
				if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
					return render(req, 'msn:sharing/Fault.userdoesnotexist.xml', status = 500)
				chat_id = circle_id[-12:]
				groupchat = backend.user_service.get_groupchat(chat_id)
				if groupchat is None: return web.HTTPInternalServerError()
				
				if lst in (models.Lst.RL,models.Lst.PL):
					return web.HTTPInternalServerError()
				if lst == models.Lst.BL:
					bs.me_block_circle(groupchat)
	return render(req, 'msn:sharing/AddMemberResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def sharing_DeleteMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	contact_uuid = None
	circle_id = None
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		lst = models.Lst.Parse(str(find_element(membership, 'MemberRole')))
		assert lst is not None
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					try:
						contact_uuid = find_element(member, 'MembershipId').split('/', 1)[1]
					except:
						email = find_element(member, 'PassportName')
						contact_uuid = backend.util_get_uuid_from_email(email or '')
					assert contact_uuid is not None
				elif member_type == 'CircleMember':
					if find_element(member, 'Type') == 'Circle' and find_element(member, 'State') == 'Accepted':
						circle_id = find_element(member, 'CircleId')
					assert circle_id is not None
			if contact_uuid is not None:
				if contact_uuid not in detail.contacts:
					return render(req, 'msn:sharing/Fault.memberdoesnotexist.xml', status = 500)
				try:
					bs.me_contact_remove(contact_uuid, lst)
				except:
					pass
			elif circle_id is not None:
				if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
					return web.HTTPInternalServerError()
				chat_id = circle_id[-12:]
				groupchat = backend.user_service.get_groupchat(chat_id)
				if groupchat is None: return web.HTTPInternalServerError()
				
				if lst in (models.Lst.RL,models.Lst.PL):
					return web.HTTPInternalServerError()
				if lst == models.Lst.BL:
					bs.me_unblock_circle(groupchat)
	return render(req, 'msn:sharing/DeleteMemberResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABFindAll(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
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

def ab_ABFindContactsPaged(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	groupchat = None
	
	ab_id = find_element(action, 'ABId')
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
	
	groupchats = [
		groupchat
		for groupchat in backend.user_service.get_groupchat_batch(user)
		if not (
			groupchat.memberships[user.uuid].role == models.GroupChatRole.Empty
			or groupchat.memberships[user.uuid].state == models.GroupChatState.Empty
		)
	]
	
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

def ab_ABContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	nickname = None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contact = find_element(action, 'contacts/Contact')
	
	if contact is None:
		return web.HTTPInternalServerError()
	
	#type = find_element(contact, 'contactType') or 'LivePending'
	email = find_element(contact, 'passportName') or ''
	if '@' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingatsign.xml', status = 500)
	elif '.' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingdot.xml', status = 500)
	
	contact_uuid = backend.util_get_uuid_from_email(email)
	if contact_uuid is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'action_str': 'ABContactAdd',
			'email': email,
		}, status = 500)
	
	annotations = contact.findall('.//{*}annotations/{*}Annotation')
	if annotations:
		for annotation in annotations:
			name = find_element(annotation, 'Name')
			# There might be more annotations we aren't aware of, comment out strict checking for now
			#if name not in _ANNOTATION_NAMES:
			#	return web.HTTPInternalServerError()
			value = find_element(annotation, 'Value')
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
		except error.ListIsFull:
			# TODO
			return web.HTTPInternalServerError()
		except:
			pass
	
	return render(req, 'msn:abservice/ABContactAddResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'contact_uuid': contact_uuid,
	})

def ab_ABContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		contact_uuid = find_element(contact, 'contactId')
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

def ab_ABContactUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		ctc = None
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
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
		# We also aren't aware of all changeable contact properties. Comment out for now to avoid conflict with unknown queries
		#for contact_property in properties_changed:
		#	if contact_property not in _CONTACT_PROPERTIES:
		#		return web.HTTPInternalServerError()
		
		for contact_property in properties_changed:
			if contact_property == 'Anniversary':
				assert ctc is not None
				property = find_element(contact_info, 'Anniversary')
				# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
				try:
					if property not in (None,-1):
						property = str(property)
						property = datetime.strptime(property, '%Y/%m/%d')
				except:
					return web.HTTPInternalServerError()
			if contact_property == 'ContactBirthDate':
				assert ctc is not None
				property = find_element(contact_info, 'birthdate')
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
					if str(find_element(contact_location, 'contactLocationType')) not in ('ContactLocationPersonal','ContactLocationBusiness'):
						return web.HTTPInternalServerError()
					location_properties_changed = find_element(contact_location, 'Changes')
					if location_properties_changed is None:
						return web.HTTPInternalServerError()
					location_properties_changed = str(location_properties_changed).strip().split(' ')
					for location_property in location_properties_changed:
						if location_property not in _CONTACT_LOCATION_PROPERTIES:
							return web.HTTPInternalServerError()
					for location_property in location_properties_changed:
						if location_property == 'Name' and str(find_element(contact_location, 'contactLocationType')) != 'ContactLocationBusiness':
							return web.HTTPInternalServerError()
			if contact_property == 'IsMessengerUser':
				assert ctc is not None
				property = find_element(contact_info, 'isMessengerUser')
				if property is None:
					return web.HTTPInternalServerError()
			if contact_property == 'ContactEmail':
				assert ctc is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = find_element(contact_email, 'propertiesChanged')
					if email_properties_changed is None:
						return web.HTTPInternalServerError()
					email_properties_changed = str(email_properties_changed).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property not in _CONTACT_EMAIL_PROPERTIES:
							return web.HTTPInternalServerError()
					if (
						str(find_element(contact_email, 'contactEmailType')) not in (
							'ContactEmailPersonal', 'ContactEmailBusiness', 'ContactEmailMessenger', 'ContactEmailOther',
						)
					):
						return web.HTTPInternalServerError()
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				if email_primary_type not in ('Passport','ContactEmailPersonal','ContactEmailBusiness','ContactEmailOther'):
					return web.HTTPInternalServerError()
			if contact_property == 'ContactPhone':
				assert ctc is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = find_element(contact_phone, 'propertiesChanged')
					if phone_properties_changed is None:
						return web.HTTPInternalServerError()
					phone_properties_changed = str(phone_properties_changed).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property not in _CONTACT_PHONE_PROPERTIES:
							return web.HTTPInternalServerError()
					if (
						str(find_element(contact_phone, 'contactPhoneType')) not in (
							'ContactPhonePersonal', 'ContactPhoneBusiness', 'ContactPhoneMobile', 'ContactPhoneFax', 'ContactPhonePager', 'ContactPhoneOther',
						),
					):
						return web.HTTPInternalServerError()
			if contact_property == 'ContactWebSite':
				assert ctc is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					if str(find_element(contact_website, 'contactWebSiteType')) not in ('ContactWebSitePersonal','ContactWebSiteBusiness'):
						return web.HTTPInternalServerError()
			if contact_property == 'Annotation':
				if find_element(contact_info, 'contactType') != 'Me':
					if ctc is None:
						return web.HTTPInternalServerError()
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					#if name not in _ANNOTATION_NAMES:
					#	return web.HTTPInternalServerError()
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
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
		if find_element(contact_info, 'contactType') != 'Me':
			if ctc is None:
				return web.HTTPInternalServerError()
	for contact in contacts:
		updated = False
		ctc = None
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
		if contact_uuid is not user.uuid and contact_uuid is not None:
			ctc = detail.contacts.get(contact_uuid)
		properties_changed = str(contact.find('./{*}propertiesChanged')).strip().split(' ')
		
		for contact_property in properties_changed:
			if contact_property == 'ContactFirstName':
				assert ctc is not None
				property = find_element(contact_info, 'firstName')
				ctc.detail.first_name = property
				updated = True
			if contact_property == 'ContactLastName':
				assert ctc is not None
				property = find_element(contact_info, 'lastName')
				ctc.detail.last_name = property
				updated = True
			# TODO: `ContactQuickName`
			# <ABContactUpdate xmlns="http://www.msn.com/webservices/AddressBook">
			#   <abId>00000000-0000-0000-0000-000000000000</abId>
			#   <contacts>
			#     <Contact xmlns="http://www.msn.com/webservices/AddressBook">
			#        <contactId>074606e9-00c5-4ccc-ba6c-b638c4b1547f</contactId>
			#        <contactInfo>
			#           <quickName>BobRoss 1</quickName>
			#        </contactInfo>
			#        <propertiesChanged>ContactQuickName</propertiesChanged>
			#     </Contact>
			#   </contacts>
			# </ABContactUpdate>
			if contact_property == 'MiddleName':
				assert ctc is not None
				property = find_element(contact_info, 'MiddleName')
				ctc.detail.middle_name = property
				updated = True
			if contact_property == 'Anniversary':
				assert ctc is not None
				property = find_element(contact_info, 'Anniversary')
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
				property = find_element(contact_info, 'birthdate')
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
				property = find_element(contact_info, 'comment')
				if property is not None:
					property = str(property)
				ctc.detail.notes = property
				updated = True
			if contact_property == 'ContactLocation':
				assert ctc is not None
				contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
				for contact_location in contact_locations:
					contact_location_type = str(find_element(contact_location, 'contactLocationType'))
					location_properties_changed = str(find_element(contact_location, 'Changes')).strip().split(' ')
					if contact_location_type not in ctc.detail.locations:
						ctc.detail.locations[contact_location_type] = models.ContactLocation(contact_location_type)
					for location_property in location_properties_changed:
						if location_property == 'Name':
							property = find_element(contact_location, 'name')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].name = property
							updated = True
						if location_property == 'Street':
							property = find_element(contact_location, 'street')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].street = property
							updated = True
						if location_property == 'City':
							property = find_element(contact_location, 'city')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].city = property
							updated = True
						if location_property == 'State':
							property = find_element(contact_location, 'state')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].state = property
							updated = True
						if location_property == 'Country':
							property = find_element(contact_location, 'country')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].country = property
							updated = True
						if location_property == 'PostalCode':
							property = find_element(contact_location, 'postalCode')
							if property is not None:
								property = str(property)
							ctc.detail.locations[contact_location_type].zip_code = property
							updated = True
					if (
						ctc.detail.locations[contact_location_type].street is None
						and ctc.detail.locations[contact_location_type].city is None
						and ctc.detail.locations[contact_location_type].state is None
						and ctc.detail.locations[contact_location_type].country is None
						and ctc.detail.locations[contact_location_type].zip_code is None
					):
						del ctc.detail.locations[contact_location_type]
						updated = True
			if contact_property == 'IsMessengerUser':
				assert ctc is not None
				property = find_element(contact_info, 'isMessengerUser')
				ctc.is_messenger_user = property
				updated = True
			if contact_property == 'ContactEmail':
				assert ctc is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = str(find_element(contact_email, 'propertiesChanged')).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property == 'Email':
							email = contact_email.find('./{*}email')
							if email is not None:
								email = str(email)
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailPersonal':
								ctc.detail.personal_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailBusiness':
								ctc.detail.work_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailMessenger':
								ctc.detail.im_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailOther':
								ctc.detail.other_email = email
							updated = True
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				ctc.detail.primary_email_type = email_primary_type
				updated = True
			if contact_property == 'ContactPhone':
				assert ctc is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = str(find_element(contact_phone, 'propertiesChanged')).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property == 'Number':
							phone_number = contact_phone.find('./{*}number')
							if phone_number is not None:
								phone_number = str(phone_number)
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePersonal':
								ctc.detail.home_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneBusiness':
								ctc.detail.work_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneFax':
								ctc.detail.fax_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePager':
								ctc.detail.pager_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneMobile':
								ctc.detail.mobile_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneOther':
								ctc.detail.other_phone = phone_number
							updated = True
			if contact_property == 'ContactWebSite':
				assert ctc is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					contact_website_type = str(find_element(contact_website, 'contactWebSiteType'))
					website = str(find_element(contact_website, 'webURL'))
					if contact_website_type == 'ContactWebSitePersonal':
						ctc.detail.personal_website = website
					if contact_website_type == 'ContactWebSiteBusiness':
						ctc.detail.business_website = website
					updated = True
			if contact_property == 'Annotation':
				if contact_uuid is not None:
					if find_element(contact_info, 'contactType') != 'Me' and not ctc:
						continue
				else:
					continue
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
					if name == 'MSN.IM.GTC':
						if value == '':
							gtc = GTCAnnotation.Empty
						else:
							gtc = GTCAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'gtc': None if gtc is GTCAnnotation.Empty else gtc.name })
						continue
					if name == 'MSN.IM.BLP':
						if value == '':
							blp = BLPAnnotation.Empty
						else:
							blp = BLPAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'blp': None if blp is BLPAnnotation.Empty else blp.name })
						continue
					if name == 'MSN.IM.MPOP':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'mpop': None if value in ('', None) else value })
						continue
					if name == 'MSN.IM.RoamLiveProperties':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'rlp': value })
						continue
					if name == 'MSN.IM.HasSharedFolder':
						# This will have to be stored in `_front_data` somehow. Ignore for now
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

def ab_ABGroupAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	name = find_element(action, 'name')
	is_favorite = find_element(action, 'IsFavorite')
	assert isinstance(is_favorite, bool) or is_favorite is None
	
	if name == '(No Group)':
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if len(name) > MAX_GROUP_NAME_LENGTH:
		return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if detail.get_groups_by_name(name):
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	group = bs.me_group_add(name, is_favorite = is_favorite)
	return render(req, 'msn:abservice/ABGroupAddResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'group_id': group.uuid,
	})

def ab_ABGroupUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	groups = action.findall('.//{*}groups/{*}Group')
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		if group_id not in detail._groups_by_uuid:
			return web.HTTPInternalServerError()
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		if not properties_changed:
			return web.HTTPInternalServerError()
		properties_changed = str(properties_changed).strip().split(' ')
		#for contact_property in properties_changed:
		#	if contact_property not in _CONTACT_PROPERTIES:
		#		return web.HTTPInternalServerError()
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
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
				
				if detail.get_groups_by_name(name):
					return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				if not isinstance(is_favorite, bool):
					return web.HTTPInternalServerError()
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		properties_changed = str(properties_changed).strip().split(' ')
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
				bs.me_group_edit(group_id, new_name = name)
			# What's the `propertiesChanged` value for the favourite setting? Check for the node for now
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				bs.me_group_edit(group_id, is_favorite = is_favorite)
	return render(req, 'msn:abservice/ABGroupUpdateResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
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

def ab_ABGroupContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
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
	
	if find_element(action, 'contactInfo') is not None:
		email = find_element(action, 'passportName')
		if email is None:
			email = find_element(action, 'email')
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
		contact_uuid = find_element(action, 'contactId')
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

def ab_ABGroupContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'abId')
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
	
	contact_uuid = find_element(action, 'contactId')
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

def sharing_CreateCircle(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	
	if (
		find_element(action, 'Domain') == 1
		and find_element(action, 'HostedDomain') == 'live.com'
		and find_element(action, 'Type') == 2
		and isinstance(find_element(action, 'IsPresenceEnabled'), bool)
	):
		membership_access = int(find_element(action, 'MembershipAccess'))
		name = str(find_element(action, 'DisplayName'))
		owner_friendly = str(find_element(action, 'PublicDisplayName'))
		
		groupchat = bs.me_create_groupchat(name, owner_friendly, membership_access)
		
		backend.loop.create_task(_dispatch_groupchat_created(backend, user, groupchat))
		
		return render(req, 'msn:sharing/CreateCircleResponse.xml', {
			'cachekey': cachekey,
			'host': settings.LOGIN_HOST,
			'session_id': util.misc.gen_uuid(),
			'chat_id': groupchat.chat_id,
		})
	
	return web.HTTPInternalServerError()

def ab_CreateContact(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	# Used as a step in Circle invites, but also used for regular contact adds in WLM 2011/2012
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if not (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12):
		return web.HTTPInternalServerError()
	
	chat_id = ab_id[-12:]
	groupchat = backend.user_service.get_groupchat(chat_id)
	
	if groupchat is None:
		return web.HTTPInternalServerError()
	
	caller_membership = groupchat.memberships.get(user.uuid)
	if caller_membership is None or caller_membership.role not in (models.GroupChatRole.Admin,models.GroupChatRole.AssistantAdmin):
		return web.HTTPInternalServerError()
	
	contact_email = find_element(action, 'Email')
	contact_uuid = backend.util_get_uuid_from_email(contact_email)
	
	if contact_uuid is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'action_str': 'CreateContact',
			'email': contact_email,
		}, status = 500)
	head = backend._load_user_record(contact_uuid)
	if head is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'action_str': 'CreateContact',
			'email': contact_email,
		}, status = 500)
	
	membership = groupchat.memberships.get(head.uuid)
	
	if (
		membership is not None and (
			membership.state == models.GroupChatState.Rejected
			or (membership.role == models.GroupChatRole.Member and membership.state == models.GroupChatState.Empty)
		)
	):
		bs.me_change_groupchat_membership(groupchat, head, role = models.GroupChatRole.Empty, state = models.GroupChatState.Empty)
	else:
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

def ab_ManageWLConnection(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	now_str = util.misc.date_format(datetime.utcnow())
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
		return web.HTTPInternalServerError()
	
	groupchat = None
	invite_message = None
	circle_mode = False
	
	contact_uuid = find_element(action, 'contactId')
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
			return web.HTTPInternalServerError()
	
	if find_element(action, 'connection') == True:
		try:
			relationship_type = models.RelationshipType(find_element(action, 'relationshipType'))
			relationship_role = int(find_element(action, 'relationshipRole'))
			wl_action = int(find_element(action, 'action'))
		except ValueError:
			return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
				'cachekey': cachekey,
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'error': 'Relationship variables invalid',
			}, status = 500)
		
		if relationship_type == models.RelationshipType.Circle:
			if groupchat is None:
				return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
					'cachekey': cachekey,
					'host': settings.LOGIN_HOST,
					'session_id': util.misc.gen_uuid(),
					'error': 'Relationship type not suitable for non-specialized contacts',
				}, status = 500)
			
			if wl_action == 1:
				if relationship_role == 0:
					if ab_id == '00000000-0000-0000-0000-000000000000':
						try:
							bs.me_accept_groupchat_invite(groupchat, send_events = False)
							backend.loop.create_task(_dispatch_groupchat_invite_status(backend, user, groupchat, False))
						except error.MemberNotInGroupChat:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.LOGIN_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': 'User `{email}` does not have membership in `GroupChat`'.format(email = head.email),
							}, status = 500)
						except error.MemberAlreadyInGroupChat:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.LOGIN_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': 'User `{email}` already accepted in `GroupChat`'.format(email = head.email),
							})
						except error.GroupChatDoesNotExist:
							return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
								'cachekey': cachekey,
								'host': settings.LOGIN_HOST,
								'session_id': util.misc.gen_uuid(),
								'error': '`GroupChat` does not currently exist',
							}, status = 500)
				elif relationship_role == 3:
					caller_membership = groupchat.memberships.get(user.uuid)
					if caller_membership is None or caller_membership.role not in (models.GroupChatRole.Admin,models.GroupChatRole.AssistantAdmin):
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.LOGIN_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': 'Caller is not in `GroupChat` or does not have sufficient privileges to perform this action',
						}, status = 500)
					
					annotations = action.findall('.//{*}annotations/{*}Annotation')
					for annotation in annotations:
						name = find_element(annotation, 'Name')
						value = find_element(annotation, 'Value')
						
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
							'error': 'User `{email}` does not have membership in `GroupChat`'.format(email = head.email),
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
						'error': 'RelationshipRole `{role}` not currently supported for relationship type `{type}`'.format(
							role = relationship_role, type = relationship_type.name
						),
					}, status = 500)
			elif wl_action == 2:
				if ab_id == '00000000-0000-0000-0000-000000000000':
					try:
						bs.me_decline_groupchat_invite(groupchat, send_events = False)
						backend.loop.create_task(_dispatch_groupchat_invite_status(backend, user, groupchat, False))
					except error.MemberNotInGroupChat:
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.LOGIN_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': 'User `{email}` does not have membership in `GroupChat`'.format(email = head.email),
						}, status = 500)
					except error.MemberAlreadyInGroupChat:
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.LOGIN_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': 'User `{email}` already accepted in `GroupChat`'.format(email = head.email),
						})
					except error.GroupChatDoesNotExist:
						return render(req, 'msn:abservice/ManageWLConnectionResponse.xml', {
							'cachekey': cachekey,
							'host': settings.LOGIN_HOST,
							'session_id': util.misc.gen_uuid(),
							'error': '`GroupChat` does not currently exist',
						}, status = 500)
			else:
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

def ab_BreakConnection(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	backend: Backend = req.app['backend']
	cachekey = secrets.token_urlsafe(172)
	
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if not (ab_id == '00000000-0000-0000-0000-000000000000' or (ab_id.startswith('00000000-0000-0000-0009-') and len(ab_id[24:]) == 12)):
		return web.HTTPInternalServerError()
	
	groupchat = None
	chat_id = None
	circle_mode = False
	
	contact_uuid = find_element(action, 'contactId')
	assert contact_uuid is not None
	if ab_id != '00000000-0000-0000-0000-000000000000':
		# Right now, this only supports requests from the calling user
		if contact_uuid != user.uuid:
			return web.HTTPInternalServerError()
		head = user
	
	if head is None:
		return render(req, 'msn:abservice/Fault.contactdoesnotexist.xml', {
			'action_str': 'BreakConnection',
		}, status = 500)
	
	if ab_id.startswith('00000000-0000-0000-0009-'):
		chat_id = ab_id[-12:]
		uuid = contact_uuid
		circle_mode = True
	
	if circle_mode:
		assert chat_id is not None
		groupchat = backend.user_service.get_groupchat(chat_id)
		if groupchat is None or uuid not in groupchat.memberships:
			return web.HTTPInternalServerError()
		
		try:
			bs.me_leave_groupchat(groupchat)
		except:
			return web.HTTPInternalServerError()
		
		backend.loop.create_task(_dispatch_groupchat_left(backend, user, groupchat))
	
	return render(req, 'msn:abservice/BreakConnectionResponse.xml', {
		'cachekey': cachekey,
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

async def _dispatch_groupchat_created(backend: Backend, user: models.User, groupchat: models.GroupChat) -> None:
	await asyncio.sleep(0.2)
	for sess in backend.util_get_sessions_by_user(user):
		sess.evt.on_groupchat_created(groupchat)

async def _dispatch_groupchat_invite_status(backend: Backend, user: models.User, groupchat: models.GroupChat, accepted: bool) -> None:
	await asyncio.sleep(0.2)
	if accepted:
		for sess in backend.util_get_sessions_by_user(user):
			sess.evt.on_accepted_groupchat_invite(groupchat)
	else:
		chat = backend.chat_get('persistent', groupchat.chat_id)
		if chat is None: return
		for sess in backend.util_get_sessions_by_user(user):
			sess.evt.on_declined_chat_invite(chat, group_chat = True)

async def _dispatch_groupchat_left(backend: Backend, user: models.User, groupchat: models.GroupChat) -> None:
	await asyncio.sleep(0.2)
	for sess in backend.util_get_sessions_by_user(user):
		sess.evt.on_left_groupchat(groupchat)

def ab_UpdateDynamicItem(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	# TODO: UpdateDynamicItem
	return unknown_soap(req, header, action, expected = True)

#_CONTACT_PROPERTIES = (
#	'Comment', 'DisplayName', 'ContactType', 'ContactFirstName', 'ContactLastName', 'MiddleName', 'Anniversary',
#	'ContactBirthDate', 'ContactEmail', 'ContactLocation', 'ContactWebSite', 'ContactPrimaryEmailType', 'ContactPhone', 'GroupName',
#	'IsMessengerEnabled', 'IsMessengerUser', 'IsFavorite', 'HasSpace',
#	'Annotation', 'Capability', 'MessengerMemberInfo',
#)

_CONTACT_PHONE_PROPERTIES = (
	'Number',
)

_CONTACT_EMAIL_PROPERTIES = (
	'Email',
)

_CONTACT_LOCATION_PROPERTIES = (
	'Name', 'Street', 'City', 'State', 'Country', 'PostalCode',
)

#_ANNOTATION_NAMES = (
#	'MSN.IM.InviteMessage', 'MSN.IM.MPOP', 'MSN.IM.BLP', 'MSN.IM.GTC', 'MSN.IM.RoamLiveProperties',
#	'MSN.IM.MBEA', 'MSN.IM.BuddyType', 'MSN.IM.HasSharedFolder', 'AB.NickName', 'AB.Profession', 'AB.Spouse',
#	'AB.JobTitle', 'Live.Locale', 'Live.Profile.Expression.LastChanged',
#	'Live.Passport.Birthdate', 'Live.Favorite.Order',
#)

class GTCAnnotation(IntEnum):
	Empty = 0
	A = 1
	N = 2

class BLPAnnotation(IntEnum):
	Empty = 0
	AL = 1
	BL = 2
