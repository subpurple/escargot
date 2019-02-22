from typing import Optional, Tuple, Any, Iterable, List, ClassVar, Dict
from urllib.parse import quote
from hashlib import md5
import binascii
import sys
import struct
from enum import Enum, IntEnum

from util.misc import first_in_iterable, last_in_iterable, DefaultDict
from typing import Optional

from core import error, event
from core.backend import Backend, BackendSession
from core.models import User, Contact, Lst, Substatus, NetworkID

def build_presence_notif(trid: Optional[str], ctc_head: User, user_me: User, dialect: int, backend: Backend, *, bs_other: Optional['BackendSession'] = None, circle_user_bs: Optional['BackendSession'] = None, circle_id: Optional[str] = None) -> Iterable[Tuple[Any, ...]]:
	circle_owner = False
	detail = user_me.detail
	assert detail is not None
	
	ctc = detail.contacts.get(ctc_head.uuid)
	assert ctc is not None
	status = ctc.status
	head = ctc.head
	is_offlineish = status.is_offlineish()
	if is_offlineish and trid is not None:
		return
	ctc_sess = None # type: Optional['BackendSession']
	
	#if backend.util_msn_is_user_circle(head.uuid) is True and dialect >= 18:
	#	if trid:
	#		return
	#	circle_id = head.email.split('@', 1)[0]
	#	circle_metadata = backend.user_service.msn_get_circle_metadata(circle_id)
	#	if not circle_user_bs:
	#		owner_uuid = backend.util_get_uuid_from_email(circle_metadata.owner_email)
	#		if owner_uuid is None: return
	#		head = backend._load_user_record(owner_uuid)
	#		status = head.status
	#		circle_owner = True
	#	else:
	#		head = circle_user_bs.user
	#		status = head.status
	
	if is_offlineish and not ctc_head is user_me:
		if dialect >= 18:
			reply = ('FLN', encode_email_networkid(head.email, None, circle_id = circle_id)) # type: Tuple[Any, ...]
		else:
			reply = ('FLN', head.email)
		
		if 13 <= dialect <= 17:
			# Mypy incorrectly gives a type error here. Must be a bug.
			reply += (int(NetworkID.WINDOWS_LIVE),) # type: ignore
		if 13 <= dialect <= 15:
			reply += ('0',)
		elif dialect >= 16:
			if circle_owner or not circle_user_bs:
				reply += ('0:0',)
			else:
				# Most likely scenario this would pop up is in circle presence
				reply += (encode_capabilities_capabilitiesex(((circle_user_bs.front_data.get('msn_capabilities') or 0) if circle_user_bs.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), 0),)
		yield reply
		return
	
	ctc_sess = first_in_iterable(backend.util_get_sessions_by_user(head))
	assert ctc_sess is not None
	
	msn_status = MSNStatus.FromSubstatus(status.substatus)
	
	if trid: frst = ('ILN', trid) # type: Tuple[Any, ...]
	else: frst = ('NLN',)
	rst = []
	
	if 8 <= dialect <= 15:
		rst.append(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC))
	elif dialect >= 16:
		rst.append(('0:0' if circle_owner else encode_capabilities_capabilitiesex(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess.front_data.get('msn_capabilitiesex') or 0)))
	if dialect >= 9:
		rst.append(encode_msnobj(ctc_sess.front_data.get('msn_msnobj') or '<msnobj/>'))
	
	if dialect >= 18:
		yield (*frst, msn_status.name, encode_email_networkid(head.email, None, circle_id = circle_id), status.name, *rst)
	else:
		yield (*frst, msn_status.name, head.email, (int(NetworkID.WINDOWS_LIVE) if 14 <= dialect <= 17 else None), status.name, *rst)
	
	if dialect < 11:
		return
	
	ubx_payload = '<Data><PSM>{}</PSM><CurrentMedia>{}</CurrentMedia>{}</Data>'.format(
		(encode_xml_he(status.message, dialect) if dialect >= 13 else encode_xml_ne(status.message)) or '', (encode_xml_he(status.media, dialect) if dialect >= 13 else encode_xml_ne(status.media)) or '', extend_ubx_payload(dialect, backend, user_me, ctc_sess)
	).encode('utf-8')
	
	if dialect >= 18:
		yield ('UBX', encode_email_networkid(head.email, None, circle_id = circle_id), ubx_payload)
	else:
		yield ('UBX', head.email, (int(NetworkID.WINDOWS_LIVE) if 14 <= dialect <= 17 else None), ubx_payload)

def encode_email_networkid(email: str, networkid: Optional[NetworkID], *, circle_id: Optional[str] = None) -> str:
	result = '{}:{}'.format(int(networkid or NetworkID.WINDOWS_LIVE), email)
	if circle_id:
		result = '{};via=9:{}@live.com'.format(result, circle_id)
	return result

def decode_email_networkid(email_networkid: str) -> Tuple[NetworkID, str]:
	parts = email_networkid.split(':', 1)
	networkid = NetworkID(int(parts[0]))
	return networkid, parts[1]

def encode_msnobj(msnobj: Optional[str]) -> Optional[str]:
	if msnobj is None: return None
	return quote(msnobj, safe = '')

def encode_xml_he(data: Optional[str], dialect: int) -> Optional[str]:
	if data is None: return None
	encoded = data.replace('&', '&#x26;')
	if dialect >= 16:
		encoded = encoded.replace('<', '&#x3C;').replace('>', '&#x3E;').replace('=', '&#x3D;').replace('\\', '&#x5C;')
	return encoded

def encode_xml_ne(data: Optional[str]) -> Optional[str]:
	if data is None: return None
	encoded = data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\'', '&apos;').replace('"', '&quot;')
	return encoded

def encode_capabilities_capabilitiesex(capabilities: int, capabilitiesex: int) -> str:
	return '{}:{}'.format(capabilities, capabilitiesex)

def decode_capabilities_capabilitiesex(capabilities_encoded: str) -> Optional[Tuple[int, int]]:
	if capabilities_encoded.find(':') > 0:
		a, b = capabilities_encoded.split(':', 1)
		return int(a), int(b)
	return int(capabilities_encoded), 0

def cid_format(uuid: str, *, decimal: bool = False) -> str:
	cid = (uuid[19:23] + uuid[24:36]).lower()
	
	if not decimal:
		return cid
	
	# convert to decimal string
	return str(struct.unpack('<q', binascii.unhexlify(cid))[0])

def encode_email_pop(email: str, pop_id: Optional[str]) -> str:
	result = email
	if pop_id:
		result = '{};{}'.format(result, '{' + pop_id + '}')
	return result

def decode_email_pop(s: str) -> Tuple[str, Optional[str]]:
	# Split `foo@email.com;{uuid}` into (email, pop_id)
	parts = s.split(';', 1)
	if len(parts) < 2:
		pop_id = None
	else:
		pop_id = parts[1]
	return (parts[0], pop_id)

def extend_ubx_payload(dialect: int, backend: Backend, user: User, ctc_sess: 'BackendSession') -> str:
	response = ''
	
	ctc_machineguid = ctc_sess.front_data.get('msn_machineguid')
	pop_id_ctc = ctc_sess.front_data.get('msn_pop_id')
	if dialect >= 13 and ctc_machineguid: response += '<MachineGuid>{}</MachineGuid>'.format(ctc_machineguid)
	
	if dialect >= 16:
		response += '{}<SignatureSound>{}</SignatureSound>{}'.format(
			('<DDP>{}</DDP>'.format(encode_xml_he(ctc_sess.front_data.get('msn_msnobj_ddp'), dialect) or '') if dialect >= 18 else ''), encode_xml_he(ctc_sess.front_data.get('msn_sigsound'), dialect) or '', ('<Scene>{}</Scene><ColorScheme>{}</ColorScheme>'.format(encode_xml_he(ctc_sess.front_data.get('msn_msnobj_scene'), dialect) or '', ctc_sess.front_data.get('msn_colorscheme') or '') if dialect >= 18 else ''),
		)
		if pop_id_ctc:
			response += EPDATA_PAYLOAD.format(mguid = '{' + pop_id_ctc + '}', capabilities = encode_capabilities_capabilitiesex(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess.front_data.get('msn_capabilitiesex') or 0))
			for ctc_sess_other in backend.util_get_sessions_by_user(ctc_sess.user):
				pop_id = ctc_sess_other.front_data.get('msn_pop_id') or ''
				if pop_id.lower() == pop_id_ctc.lower(): continue
				response += EPDATA_PAYLOAD.format(
					mguid = '{' + pop_id + '}',
					capabilities = encode_capabilities_capabilitiesex(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess_other.front_data.get('msn_capabilitiesex') or 0)
				)
			if ctc_sess.user is user:
				for ctc_sess_other in backend.util_get_sessions_by_user(ctc_sess.user):
					ped_data = ''
					if ctc_sess_other.front_data.get('msn_epname'):
						ped_data += PRIVATEEPDATA_EPNAME_PAYLOAD.format(epname = ctc_sess_other.front_data['msn_epname'])
					if ctc_sess_other.front_data.get('msn_endpoint_idle'):
						ped_data += PRIVATEEPDATA_IDLE_PAYLOAD.format(idle = ('true' if ctc_sess_other.front_data['msn_endpoint_idle'] else 'false'))
					if ctc_sess_other.front_data.get('msn_client_type'):
						ped_data += PRIVATEEPDATA_CLIENTTYPE_PAYLOAD.format(ct = ctc_sess_other.front_data['msn_client_type'])
					if ctc_sess_other.front_data.get('msn_ep_state'):
						ped_data += PRIVATEEPDATA_STATE_PAYLOAD.format(state = ctc_sess_other.front_data['msn_ep_state'])
					response += PRIVATEEPDATA_PAYLOAD.format(mguid = '{' + (ctc_sess_other.front_data.get('msn_pop_id') or '') + '}', ped_data = ped_data)
	return response

#def gen_signedticket_xml(user: User, backend: Backend) -> str:
#	circleticket_data = backend.user_service.msn_get_circleticket(user.uuid)
#	return '<?xml version="1.0" encoding="utf-16"?>\r\n<SignedTicket xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ver="1" keyVer="1">\r\n  <Data>{}</Data>\r\n  <Sig>{}</Sig>\r\n</SignedTicket>'.format(
#		circleticket_data[0], circleticket_data[1],
#	)

def gen_chal_response(chal: str, id: str, id_key: str, *, msnp11: bool = False) -> str:
	key_hash = md5((chal + id_key).encode())
	
	if not msnp11:
		return key_hash.hexdigest()
	
	# TODO: MSNP11 challenge/response procedure
	return 'PASS'

def gen_mail_data(user: User, backend: Backend, *, oim_uuid: Optional[str] = None, just_sent: bool = False, on_ns: bool = True, e_node: bool = True, q_node: bool = True) -> str:
	md_m_pl = ''
	if just_sent:
		oim_collection = backend.user_service.msn_get_oim_single(user.email, oim_uuid or '')
	else:
		oim_collection = backend.user_service.msn_get_oim_batch(user.email)
	if on_ns and len(oim_collection) > 25: return 'too-large'
	
	for oim in oim_collection:
		md_m_pl += M_MAIL_DATA_PAYLOAD.format(
			rt = (RT_M_MAIL_DATA_PAYLOAD.format(
				senttime = (oim.last_oim_sent.isoformat()[:19] + 'Z')
			) if not just_sent else ''), oimsz = oim.oim_content_length,
			frommember = oim.from_member_name, guid = oim.run_id, fid = ('00000000-0000-0000-0000-000000000009' if not just_sent else '.!!OIM'),
			fromfriendly = (oim.from_member_friendly if not just_sent else _format_friendly(oim.from_member_friendly)),
			su = ('<SU> </SU>' if just_sent else ''),
		)
	
	return MAIL_DATA_PAYLOAD.format(
		e = (E_MAIL_DATA_PAYLOAD if e_node else ''),
		q = (Q_MAIL_DATA_PAYLOAD if q_node else ''),
		m = md_m_pl,
	)

def _format_friendly(friendlyname: str) -> str:
	friendly_parts = friendlyname.split('?')
	friendly_parts[3] += ' '
	return '?'.join(friendly_parts)

MAIL_DATA_PAYLOAD = '<MD>{e}{q}{m}</MD>'

E_MAIL_DATA_PAYLOAD = '<E><I>0</I><IU>0</IU><O>0</O><OU>0</OU></E>'

Q_MAIL_DATA_PAYLOAD = '<Q><QTM>409600</QTM><QNM>204800</QNM></Q>'

M_MAIL_DATA_PAYLOAD = '<M><T>11</T><S>6</S>{rt}<RS>0</RS><SZ>{oimsz}</SZ><E>{frommember}</E><I>{guid}</I><F>{fid}</F><N>{fromfriendly}</N></M>{su}'

RT_M_MAIL_DATA_PAYLOAD = '<RT>{senttime}</RT>'

EPDATA_PAYLOAD = '<EndpointData id="{mguid}"><Capabilities>{capabilities}</Capabilities></EndpointData>'

PRIVATEEPDATA_PAYLOAD = '<PrivateEndpointData id="{mguid}">{ped_data}</PrivateEndpointData>'

PRIVATEEPDATA_EPNAME_PAYLOAD = '<EpName>{epname}</EpName>'

PRIVATEEPDATA_IDLE_PAYLOAD = '<Idle>{idle}</Idle>'

PRIVATEEPDATA_CLIENTTYPE_PAYLOAD = '<ClientType>{ct}</ClientType>'

PRIVATEEPDATA_STATE_PAYLOAD = '<State>{state}</State>'

#class CircleBackendEventHandler(event.BackendEventHandler):
#	__slots__ = ('bs',)
#	
#	bs: 'BackendSession'
#	
#	def __init__(self) -> None:
#		pass
#	
#	def on_system_message(self, *args: Any, **kwargs: Any) -> None:
#		pass
#	
#	def on_maintenance_boot(self) -> None:
#		pass
#	
#	def on_presence_notification(self, bs_other: Optional['BackendSession'], ctc_head: User, old_substatus: Substatus, on_contact_add: bool, *, trid: Optional[str] = None, update_status: bool = True, send_status_on_bl: bool = False, visible_notif: bool = True, updated_phone_info: Optional[Dict[str, Any]] = None, circle_user_bs: Optional['BackendSession'] = None, circle_id: Optional[str] = None) -> None:
#		bs = self.bs
#		assert bs is not None
#		backend = bs.backend
#		user_me = bs.user
#		
#		if bs_other is None or circle_user_bs not in bs.front_data.get('msn_circle_roster'):
#			return
#		
#		detail_other = backend._load_detail(ctc_head)
#		assert detail_other is not None
#		ctc_me = detail_other.contacts.get(user_me.uuid)
#		if ctc_me is not None and ctc_me.head is user_me:
#			detail = user_me.detail
#			assert detail is not None
#			ctc_other = detail.contacts.get(ctc_head.uuid)
#			# This shouldn't be `None`, since every contact should have
#			# an `RL` contact on the other users' list (at the very least).
#			if ctc_other is None or not (ctc_other.lists & Lst.FL and ctc_me.lists & Lst.AL) and not (update_status and send_status_on_bl): return
#			for ctc_other in detail.contacts.values():
#				if not ctc_other.lists & Lst.FL: continue
#				for ctc_other_sess in backend.util_get_sess_by_user(ctc_other.head):
#					ctc_other_sess.evt.on_presence_notification(bs, bs.user, ctc.status.substatus, False, circle_user_bs = bs_other, circle_id = bs.user.email.split('@', 1)[0])
#			return
#	
#	def on_sync_contact_statuses(self) -> None:
#		bs = self.bs
#		assert bs is not None
#		user = bs.user
#		detail = user.detail
#		assert detail is not None
#		
#		for ctc in detail.contacts.values():
#			if ctc.lists & Lst.FL:
#				ctc.compute_visible_status(user, is_blocking)
#			
#			# If the contact lists ever become inconsistent (FL without matching RL),
#			# the contact that's missing the RL will always see the other user as offline.
#			# Because of this, and the fact that most contacts *are* two-way, and it
#			# not being that much extra work, I'm leaving this line commented out.
#			#if not ctc.lists & Lst.RL: continue
#			
#			if ctc.head.detail is None: continue
#			ctc_rev = ctc.head.detail.contacts.get(user.uuid)
#			if ctc_rev is None: continue
#			ctc_rev.compute_visible_status(ctc.head, is_blocking)
#	
#	def on_chat_invite(self, chat: 'Chat', inviter: User, *, inviter_id: Optional[str] = None, invite_msg: str = '') -> None:
#		pass
#	
#	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional['TextWithData'] = None) -> None:
#		pass
#	
#	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str]) -> None:
#		pass
#	
#	def on_login_elsewhere(self, option: 'LoginOption') -> None:
#		pass
#	
#	def msn_on_put_sent(self, message: EmailMessage, sender: User, *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
#		bs = self.bs
#		assert bs is not None
#		
#		for bs_other in bs.front_data.get('msn_circle_roster'):
#			bs_other.evt.msn_on_put_sent(message, bs.user, pop_id_sender = None, pop_id = pop_id_sender)
#	
#	def msn_on_user_circle_presence(self, bs_other: 'BackendSession') -> None:
#		bs = self.bs
#		assert bs is not None
#		user_me = bs.user
#		
#		if bs_other not in bs.front_data.get('msn_circle_roster'):
#			bs.front_data.get('msn_circle_roster').add(bs_other)
#			self.on_presence_notification(bs, bs.user, bs.user.status.substatus, False)

MAX_CAPABILITIES_BASIC = 1073741824

class MSNStatus(Enum):
	FLN = object()
	NLN = object()
	BSY = object()
	IDL = object()
	BRB = object()
	AWY = object()
	PHN = object()
	LUN = object()
	HDN = object()
	
	@classmethod
	def ToSubstatus(cls, msn_status: 'MSNStatus') -> Substatus:
		return _ToSubstatus[msn_status]
	
	@classmethod
	def FromSubstatus(cls, substatus: 'Substatus') -> 'MSNStatus':
		return _FromSubstatus[substatus]

_ToSubstatus = DefaultDict(Substatus.Busy, {
	MSNStatus.FLN: Substatus.Offline,
	MSNStatus.NLN: Substatus.Online,
	MSNStatus.BSY: Substatus.Busy,
	MSNStatus.IDL: Substatus.Idle,
	MSNStatus.BRB: Substatus.BRB,
	MSNStatus.AWY: Substatus.Away,
	MSNStatus.PHN: Substatus.OnPhone,
	MSNStatus.LUN: Substatus.OutToLunch,
	MSNStatus.HDN: Substatus.Invisible,
})
_FromSubstatus = DefaultDict(MSNStatus.BSY, {
	Substatus.Offline: MSNStatus.FLN,
	Substatus.Online: MSNStatus.NLN,
	Substatus.Busy: MSNStatus.BSY,
	Substatus.Idle: MSNStatus.IDL,
	Substatus.BRB: MSNStatus.BRB,
	Substatus.Away: MSNStatus.AWY,
	Substatus.OnPhone: MSNStatus.PHN,
	Substatus.OutToLunch: MSNStatus.LUN,
	Substatus.Invisible: MSNStatus.HDN,
	Substatus.NotAtHome: MSNStatus.AWY,
	Substatus.NotAtDesk: MSNStatus.BRB,
	Substatus.NotInOffice: MSNStatus.AWY,
	Substatus.OnVacation: MSNStatus.AWY,
	Substatus.SteppedOut: MSNStatus.BRB,
})

class Err:
	InvalidParameter = 201
	InvalidNetworkID = 204
	InvalidUser = 205
	DuplicateSession = 207
	InvalidUser2 = 208
	PrincipalOnList = 215
	PrincipalNotOnList = 216
	PrincipalNotOnline = 217
	AlreadyInMode = 218
	GroupInvalid = 224
	PrincipalNotInGroup = 225
	GroupAlreadyExists = 228
	GroupNameTooLong = 229
	GroupZeroUnremovable = 230
	XXLEmptyDomain = 240
	XXLInvalidPayload = 241
	InternalServerError = 500
	CommandDisabled = 502
	ChallengeResponseFailed = 540
	NotExpected = 715
	AuthFail = 911
	NotAllowedWhileHDN = 913
	InvalidCircleMembership = 933
	
	@classmethod
	def GetCodeForException(cls, exc: Exception, dialect: int) -> int:
		if isinstance(exc, error.GroupAlreadyExists):
			return cls.GroupAlreadyExists
		if isinstance(exc, error.GroupNameTooLong):
			return cls.GroupNameTooLong
		if isinstance(exc, error.GroupDoesNotExist):
			return cls.GroupInvalid
		if isinstance(exc, error.CannotRemoveSpecialGroup):
			return cls.GroupZeroUnremovable
		if isinstance(exc, error.ContactDoesNotExist):
			if dialect >= 10:
				return cls.InvalidUser2
			else:
				return cls.InvalidUser
		if isinstance(exc, error.ContactAlreadyOnList):
			return cls.PrincipalOnList
		if isinstance(exc, error.ContactNotOnList):
			return cls.PrincipalNotOnList
		if isinstance(exc, error.UserDoesNotExist):
			if dialect >= 10:
				return cls.InvalidUser2
			else:
				return cls.InvalidUser
		if isinstance(exc, error.ContactNotOnline):
			return cls.PrincipalNotOnline
		if isinstance(exc, error.AuthFail):
			return cls.AuthFail
		if isinstance(exc, error.NotAllowedWhileHDN):
			return cls.NotAllowedWhileHDN
		raise ValueError("Exception not convertible to MSNP error") from exc
