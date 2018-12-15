from typing import Optional, Tuple, Any, Iterable, List, ClassVar, Dict
from urllib.parse import quote
from hashlib import md5
import binascii
import sys
import struct
from enum import Enum, IntEnum

from util.misc import first_in_iterable, DefaultDict
from typing import Optional

from core import error
from core.backend import Backend
from core.models import User, Contact, Lst, Substatus, NetworkID

def build_presence_notif(trid: Optional[str], ctc: Contact, dialect: int, backend: Backend, old_substatus: Substatus, *, circle_user_bs: Optional['BackendSession'] = None, circle_id: Optional[str] = None) -> Iterable[Tuple[Any, ...]]:
	circle_owner = False
	
	status = ctc.status
	is_offlineish = status.is_offlineish()
	if is_offlineish and trid is not None:
		return
	ctc_sess = None # type: Optional['BackendSession']
	head = ctc.head
	
	networkid = None # type: Optional[NetworkID]
	if dialect >= 14:
		networkid = convert_networkid_to_msn_friendly(head.networkid)
	
	if head.networkid is NetworkID.CIRCLE and dialect >= 18:
		if trid:
			return
		circle_id = head.email.split('@', 1)[0]
		circle_metadata = backend.user_service.msn_get_circle_metadata(circle_id)
		if not circle_user_bs:
			owner_uuid = backend.util_get_uuid_from_email(circle_metadata.owner_email, NetworkID.WINDOWS_LIVE)
			if owner_uuid is None: return
			head = backend._load_user_record(owner_uuid)
			networkid = head.networkid
			circle_owner = True
		else:
			head = circle_user_bs.user
			networkid = head.networkid
	
	ctc_sess_list = backend.util_get_sessions_by_user(head)
	if len(ctc_sess_list) > 0:
		ctc_sess = ctc_sess_list[len(ctc_sess_list) - 1]
		assert ctc_sess is not None
	
	if is_offlineish and old_substatus not in (Substatus.Offline,Substatus.Invisible):
		if dialect >= 18:
			yield ('FLN', encode_email_networkid(head.email, networkid, circle_id = circle_id), ('0:0' if circle_owner else encode_capabilities_capabilitiesex(ctc_sess.front_data.get('msn_capabilities') or 0, ctc_sess.front_data.get('msn_capabilitiesex') or 0)))
		else:
			reply = ('FLN', head.email)
			if dialect >= 14: reply += ((int(networkid) if networkid else 1),)
			yield reply
		return
	
	msn_status = MSNStatus.FromSubstatus(status.substatus)
	
	if trid: frst = ('ILN', trid) # type: Tuple[Any, ...]
	else: frst = ('NLN',)
	rst = []
	
	if 8 <= dialect <= 15:
		rst.append(ctc_sess.front_data.get('msn_capabilities') or 0)
	elif dialect >= 18:
		rst.append(('0:0' if circle_owner else encode_capabilities_capabilitiesex(ctc_sess.front_data.get('msn_capabilities') or 0, ctc_sess.front_data.get('msn_capabilitiesex') or 0)))
	if dialect >= 9:
		rst.append(encode_msnobj(ctc_sess.front_data.get('msn_msnobj') or '<msnobj/>'))
	
	if dialect >= 16:
		yield (*frst, msn_status.name, encode_email_networkid(head.email, networkid, circle_id = circle_id), status.name, *rst)
	else:
		yield (*frst, msn_status.name, head.email, ((int(networkid) if networkid else 1) if 14 <= dialect <= 16 else None), status.name, *rst)
	
	if dialect < 11:
		return
	
	ubx_payload = '<Data><PSM>{}</PSM><CurrentMedia>{}</CurrentMedia>{}</Data>'.format(
		(encode_xml_he(status.message, dialect) if dialect >= 13 else encode_xml_ne(status.message)) or '', (encode_xml_he(status.media, dialect) if dialect >= 13 else encode_xml_ne(status.media)) or '', extend_ubx_payload(dialect, backend, ctc_sess)
	).encode('utf-8')
	
	if dialect >= 18:
		yield ('UBX', encode_email_networkid(head.email, networkid, circle_id = circle_id), ubx_payload)
	elif dialect >= 11:
		yield ('UBX', head.email, ((int(networkid) if networkid else 1) if 14 <= dialect <= 16 else None), ubx_payload)

def encode_email_networkid(email: str, networkid: Optional[NetworkID], *, circle_id: Optional[str] = None) -> str:
	result = '{}:{}'.format((int(networkid) if networkid else 1), email)
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
	if dialect >= 18:
		encoded = encoded.replace('<', '&#x3C;').replace('>', '&#x3E;').replace('=', '&#x3D;').replace('\\', '&#x5C;')
	return encoded

def encode_xml_ne(data: Optional[str]) -> Optional[str]:
	if data is None: return None
	encoded = data.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('\'', '&apos;').replace('"', '&quot;')
	return encoded

def encode_capabilities_capabilitiesex(capabilities: int, capabilitiesex: int) -> str:
	return '{}:{}'.format(capabilities, capabilitiesex)

def decode_capabilities_capabilitiesex(capabilities_encoded: str) -> Optional[Tuple[int, int]]:
	return (capabilities_encoded.split(':', 1) if capabilities_encoded.find(':') > 0 else None)

def cid_format(uuid: str, *, decimal: bool = False) -> str:
	cid = (uuid[0:8] + uuid[28:36])[::-1].lower()
	
	if not decimal:
		return cid
	
	# convert to decimal string
	return str(int(cid, 16))

def decode_email_pop(s: str) -> Tuple[str, Optional[str]]:
	# Split `foo@email.com;{uuid}` into (email, pop_id)
	parts = s.split(';', 1)
	if len(parts) < 2:
		pop_id = None
	else:
		pop_id = parts[1]
	return (parts[0], pop_id)

def extend_ubx_payload(dialect: int, backend: Backend, ctc_sess: 'BackendSession') -> str:
	response = ''
	
	ctc_machineguid = ctc_sess.front_data.get('msn_machineguid')
	pop_id_ctc = ctc_sess.front_data.get('msn_pop_id')
	if dialect >= 13 and ctc_machineguid: response += '<MachineGuid>{}</MachineGuid>'.format(ctc_machineguid)
	
	if dialect >= 18:
		response += '<DDP>{}</DDP><SignatureSound>{}</SignatureSound><Scene>{}</Scene><ColorScheme>{}</ColorScheme>'.format(
			encode_xml_he(ctc_sess.front_data.get('msn_msnobj_ddp'), dialect) or '', encode_xml_he(ctc_sess.front_data.get('msn_sigsound'), dialect) or '', encode_xml_he(ctc_sess.front_data.get('msn_msnobj_scene'), dialect) or '', ctc_sess.front_data.get('msn_colorscheme') or '',
		)
		if pop_id_ctc:
			response += EPDATA_PAYLOAD.format(mguid = '{' + pop_id_ctc + '}', capabilities = encode_capabilities_capabilitiesex(ctc_sess.front_data.get('msn_capabilities') or 0, ctc_sess.front_data.get('msn_capabilitiesex') or 0))
			for ctc_sess_other in backend.util_get_sessions_by_user(ctc_sess.user):
				if ctc_sess_other.front_data.get('msn_pop_id') == pop_id_ctc: continue
				response += EPDATA_PAYLOAD.format(mguid = '{' + ctc_sess_other.front_data.get('msn_pop_id') + '}', capabilities = encode_capabilities_capabilitiesex(ctc_sess_other.front_data.get('msn_capabilities') or 0, ctc_sess_other.front_data.get('msn_capabilitiesex') or 0))
	return response

def is_blocking(blocker: User, blockee: User) -> bool:
	detail = blocker.detail
	assert detail is not None
	contact = detail.contacts.get(blockee.uuid)
	lists = (contact and contact.lists or 0)
	if lists & Lst.BL: return True
	if lists & Lst.AL: return False
	return (blocker.settings.get('BLP', 'AL') == 'BL')

def gen_signedticket_xml(user: User, backend: Backend) -> str:
	circleticket_data = backend.user_service.msn_get_circleticket(user.uuid)
	return '<?xml version="1.0" encoding="utf-16"?>\r\n<SignedTicket xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ver="1" keyVer="1">\r\n  <Data>{}</Data>\r\n  <Sig>{}</Sig>\r\n</SignedTicket>'.format(
		circleticket_data[0], circleticket_data[1],
	)

def convert_networkid_to_msn_friendly(networkid: NetworkID) -> NetworkID:
	if networkid in (NetworkID.ANY,NetworkID.IRC):
		return NetworkID.WINDOWS_LIVE
	return networkid

def gen_chal_response(chal: str, id: str, id_key: str, *, msnp11: bool = False) -> str:
	key_hash = md5((chal + id_key).encode())
	
	if not msnp11:
		return key_hash.hexdigest()
	
	if msnp11:
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
	InvalidPrincipal = 205
	DuplicateSession = 207
	InvalidPrincipal2 = 208
	PrincipalOnList = 215
	PrincipalNotOnList = 216
	PrincipalNotOnline = 217
	AlreadyInMode = 218
	GroupInvalid = 224
	PrincipalNotInGroup = 225
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
		if isinstance(exc, error.GroupNameTooLong):
			return cls.GroupNameTooLong
		if isinstance(exc, error.GroupDoesNotExist):
			return cls.GroupInvalid
		if isinstance(exc, error.CannotRemoveSpecialGroup):
			return cls.GroupZeroUnremovable
		if isinstance(exc, error.ContactDoesNotExist):
			if dialect >= 10:
				return cls.InvalidPrincipal
			else:
				return cls.InvalidPrincipal
		if isinstance(exc, error.ContactAlreadyOnList):
			return cls.PrincipalOnList
		if isinstance(exc, error.ContactNotOnList):
			return cls.PrincipalNotOnList
		if isinstance(exc, error.UserDoesNotExist):
			if dialect >= 10:
				return cls.InvalidPrincipal2
			else:
				return cls.InvalidPrincipal
		if isinstance(exc, error.ContactNotOnline):
			return cls.PrincipalNotOnline
		if isinstance(exc, error.AuthFail):
			return cls.AuthFail
		if isinstance(exc, error.NotAllowedWhileHDN):
			return cls.NotAllowedWhileHDN
		raise ValueError("Exception not convertible to MSNP error") from exc
