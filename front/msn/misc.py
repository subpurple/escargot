from typing import Optional, Tuple, Any, Iterable, List, ClassVar, Dict
from urllib.parse import quote
from hashlib import md5, sha1
import hmac
from pytz import timezone
from datetime import datetime
import base64
import binascii
import sys
from quopri import encodestring as quopri_encode
import struct
from enum import Enum, IntEnum

from util.misc import first_in_iterable, last_in_iterable, date_format, DefaultDict
from typing import Optional

from core import error, event
from core.backend import Backend, BackendSession, ChatSession
from core.models import User, Contact, GroupChat, Lst, MessageData, OIM, Substatus, NetworkID

def build_presence_notif(trid: Optional[str], ctc_head: User, user_me: User, dialect: int, backend: Backend, iln_sent: bool, *, self_presence: bool = False, bs_other: Optional['BackendSession'] = None, groupchat: Optional['GroupChat'] = None) -> Iterable[Tuple[Any, ...]]:
	detail = user_me.detail
	assert detail is not None
	
	if not iln_sent: return
	
	nfy_rst = ''
	
	if not groupchat:
		if not self_presence and ctc_head is not user_me:
			ctc = detail.contacts.get(ctc_head.uuid)
			assert ctc is not None
			status = ctc.status
			head = ctc.head
		else:
			head = user_me
			status = head.status
	else:
		head = ctc_head
		status = head.status
	is_offlineish = status.is_offlineish()
	if is_offlineish and trid is not None:
		return
	ctc_sess = None # type: Optional['BackendSession']
	
	ctc_sess = first_in_iterable(backend.util_get_sessions_by_user(head))
	
	#if dialect == 21:
	#	cm = None # type: Optional[str]
	#	pop_id_ctc = None # type: Optional[str]
	#	
	#	substatus = status.substatus
	#	
	#	if is_offlineish and head is not user_me:
	#		# In case `ctc` is going `HDN`; make sure other people don't receive `HDN` as status
	#		substatus = Substatus.Offline
	#	
	#	if not substatus is Substatus.Offline:
	#		assert ctc_sess is not None
	#		
	#		cm = NFY_PUT_PRESENCE_USER_S_CM.format(cm = encode_xml_he(status.media or '', dialect))
	#		nfy_rst += NFY_PUT_PRESENCE_USER_S_PE.format(
	#			msnobj = encode_xml_he(ctc_sess.front_data.get('msn_msnobj') or '', dialect),
	#			name = status.name or head.email, message = status.message,
	#			ddp = encode_xml_he(ctc_sess.front_data.get('msn_msnobj_ddp') or '', dialect), colorscheme = encode_xml_he(ctc_sess.front_data.get('msn_colorscheme') or '', dialect), scene = encode_xml_he(ctc_sess.front_data.get('msn_msnobj_scene') or '', dialect), sigsound = encode_xml_he(ctc_sess.front_data.get('msn_sigsound') or '', dialect),
	#		)
	#		if ctc_sess.front_data.get('msn_pop_id') is not None:
	#			pop_id_ctc = '{' + ctc_sess.front_data['msn_pop_id'] + '}'
	#		nfy_rst += NFY_PUT_PRESENCE_USER_SEP_IM.format(
	#			epid_attrib = (NFY_PUT_PRESENCE_USER_SEP_EPID.format(mguid = pop_id_ctc or '') if pop_id_ctc is not None else ''), capabilities = encode_capabilities_capabilitiesex(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess.front_data.get('msn_capabilitiesex') or 0),
	#		)
	#		if ctc_sess.front_data.get('msn_PE'):
	#			pe_data = ''
	#			pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_VER.format(ver = ctc_sess.front_data.get('msn_PE_VER') or '')
	#			pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_TYP.format(typ = ctc_sess.front_data.get('msn_PE_TYP') or '')
	#			pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_CAP.format(pe_capabilities = encode_capabilities_capabilitiesex(ctc_sess.front_data.get('msn_PE_capabilities') or 0, ctc_sess.front_data.get('msn_PE_capabilitiesex') or 0))
	#			nfy_rst += NFY_PUT_PRESENCE_USER_SEP_PE.format(
	#				epid_attrib = (NFY_PUT_PRESENCE_USER_SEP_EPID.format(mguid = pop_id_ctc or '') if pop_id_ctc is not None else ''), pe_data = pe_data,
	#			)
	#		if pop_id_ctc is not None:
	#			nfy_rst += NFY_PUT_PRESENCE_USER_SEP_PD.format(
	#				mguid = pop_id_ctc, ped_data = _list_private_endpoint_data(ctc_sess),
	#			)
	#		
	#		for ctc_sess_other in backend.util_get_sessions_by_user(ctc_sess.user):
	#			if ctc_sess_other is ctc_sess: continue
	#			if ctc_sess_other.front_data.get('msn_pop_id') is None: continue
	#			
	#			nfy_rst += NFY_PUT_PRESENCE_USER_SEP_IM.format(
	#				epid_attrib = NFY_PUT_PRESENCE_USER_SEP_EPID.format(mguid = '{' + ctc_sess_other.front_data['msn_pop_id'] + '}'), capabilities = encode_capabilities_capabilitiesex(((ctc_sess_other.front_data.get('msn_capabilities') or 0) if ctc_sess_other.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess_other.front_data.get('msn_capabilitiesex') or 0),
	#			)
	#			if ctc_sess_other.front_data.get('msn_PE'):
	#				pe_data = ''
	#				pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_VER.format(ver = ctc_sess_other.front_data.get('msn_PE_VER') or '')
	#				pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_TYP.format(typ = ctc_sess_other.front_data.get('msn_PE_TYP') or '')
	#				pe_data += NFY_PUT_PRESENCE_USER_SEP_PE_CAP.format(capabilities = encode_capabilities_capabilitiesex(ctc_sess_other.front_data.get('msn_PE_capabilities') or 0, ctc_sess_other.front_data.get('msn_PE_capabilitiesex') or 0))
	#				nfy_rst += NFY_PUT_PRESENCE_USER_SEP_PE.format(
	#					epid_attrib = NFY_PUT_PRESENCE_USER_SEP_EPID.format(mguid = '{' + ctc_sess_other.front_data['msn_pop_id'] + '}'), pe_data = pe_data,
	#				)
	#			nfy_rst += NFY_PUT_PRESENCE_USER_SEP_PD.format(
	#				mguid = '{' + ctc_sess_other.front_data['msn_pop_id'] + '}', ped_data = _list_private_endpoint_data(ctc_sess_other)
	#			)
	#	
	#	msn_status = MSNStatus.FromSubstatus(substatus)
	#	
	#	nfy_presence_body = NFY_PUT_PRESENCE_USER.format(
	#		substatus = msn_status.name, cm = cm or '', rst = nfy_rst,
	#	)
	#	
	#	nfy_payload = encode_payload(NFY_PUT_PRESENCE,
	#		to = user_me.email, from_email = head.email, cl = len(nfy_presence_body), payload = nfy_presence_body,
	#	)
	#	
	#	yield ('NFY', 'PUT', nfy_payload)
	#	return
	
	if is_offlineish and not head is user_me:
		if dialect >= 18:
			reply = ('FLN', encode_email_networkid(head.email, None, groupchat = groupchat)) # type: Tuple[Any, ...]
		else:
			reply = ('FLN', head.email)
		
		if 13 <= dialect <= 17:
			# Mypy incorrectly gives a type error here. Must be a bug.
			reply += (int(NetworkID.WINDOWS_LIVE),) # type: ignore
		if 13 <= dialect <= 15:
			reply += ('0',)
		elif dialect >= 16:
			if (groupchat is not None and head.uuid == groupchat.owner_uuid) or not (groupchat is not None and bs_other is not None):
				reply += ('0:0',)
			else:
				assert bs_other is not None
				# Most likely scenario this would pop up is in circle presence
				reply += (encode_capabilities_capabilitiesex(((bs_other.front_data.get('msn_capabilities') or 0) if bs_other.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), 0),)
		yield reply
		return
	
	assert ctc_sess is not None
	
	msn_status = MSNStatus.FromSubstatus(status.substatus)
	
	if trid and dialect < 18: frst = ('ILN', trid) # type: Tuple[Any, ...]
	else: frst = ('NLN',)
	rst = []
	
	if 8 <= dialect <= 15:
		rst.append(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC))
	elif dialect >= 16:
		rst.append(('0:0' if groupchat is not None and head.uuid == groupchat.owner_uuid else encode_capabilities_capabilitiesex(((ctc_sess.front_data.get('msn_capabilities') or 0) if ctc_sess.front_data.get('msn') is True else MAX_CAPABILITIES_BASIC), ctc_sess.front_data.get('msn_capabilitiesex') or 0)))
	if dialect >= 9:
		rst.append(encode_msnobj(ctc_sess.front_data.get('msn_msnobj') or '<msnobj/>'))
	
	if dialect >= 18:
		yield (*frst, msn_status.name, encode_email_networkid(head.email, None, groupchat = groupchat), status.name, *rst)
	else:
		yield (*frst, msn_status.name, head.email, (int(NetworkID.WINDOWS_LIVE) if 14 <= dialect <= 17 else None), status.name, *rst)
	
	if dialect < 11:
		return
	
	ubx_payload = '<Data><PSM>{}</PSM><CurrentMedia>{}</CurrentMedia>{}</Data>'.format(
		(encode_xml_he(status.message, dialect) if dialect >= 13 else encode_xml_ne(status.message)) or '', (encode_xml_he(status.media, dialect) if dialect >= 13 else encode_xml_ne(status.media)) or '', extend_ubx_payload(dialect, backend, user_me, ctc_sess)
	).encode('utf-8')
	
	if dialect >= 18:
		yield ('UBX', encode_email_networkid(head.email, None, groupchat = groupchat), ubx_payload)
	else:
		yield ('UBX', head.email, (int(NetworkID.WINDOWS_LIVE) if 14 <= dialect <= 17 else None), ubx_payload)

def encode_email_networkid(email: str, networkid: Optional[NetworkID], *, groupchat: Optional['GroupChat'] = None) -> str:
	result = '{}:{}'.format(int(networkid or NetworkID.WINDOWS_LIVE), email)
	if groupchat:
		result = '{};via=9:00000000-0000-0000-0009-{}@live.com'.format(result, groupchat.chat_id)
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
					if ctc_sess_other.front_data.get('msn_pop_id') is None: continue
					
					response += PRIVATEEPDATA_PAYLOAD.format(mguid = '{' + (ctc_sess_other.front_data.get('msn_pop_id') or '') + '}', ped_data = _list_private_endpoint_data(ctc_sess_other))
	return response

def _list_private_endpoint_data(ctc_sess: 'BackendSession') -> str:
	ped_data = ''
	
	if ctc_sess.front_data.get('msn_epname'):
		ped_data += PRIVATEEPDATA_EPNAME_PAYLOAD.format(epname = ctc_sess.front_data['msn_epname'])
	if ctc_sess.front_data.get('msn_endpoint_idle'):
		ped_data += PRIVATEEPDATA_IDLE_PAYLOAD.format(idle = ('true' if ctc_sess.front_data['msn_endpoint_idle'] else 'false'))
	if ctc_sess.front_data.get('msn_client_type'):
		ped_data += PRIVATEEPDATA_CLIENTTYPE_PAYLOAD.format(ct = ctc_sess.front_data['msn_client_type'])
	if ctc_sess.front_data.get('msn_ep_state'):
		ped_data += PRIVATEEPDATA_STATE_PAYLOAD.format(state = ctc_sess.front_data['msn_ep_state'])
	
	return ped_data

#def gen_signedticket_xml(user: User, backend: Backend) -> str:
#	circleticket_data = backend.user_service.msn_get_circleticket(user.uuid)
#	return '<?xml version="1.0" encoding="utf-16"?>\r\n<SignedTicket xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" ver="1" keyVer="1">\r\n  <Data>{}</Data>\r\n  <Sig>{}</Sig>\r\n</SignedTicket>'.format(
#		circleticket_data[0], circleticket_data[1],
#	)

def encode_payload(tmpl: str, **kwargs: Any) -> bytes:
	return tmpl.format(**kwargs).replace('\n', '\r\n').encode('utf-8')

def gen_chal_response(chal: str, id: str, id_key: str, *, msnp11: bool = False) -> str:
	key_hash = md5((chal + id_key).encode())
	
	if not msnp11:
		return key_hash.hexdigest()
	
	# TODO: MSNP11 challenge/response procedure
	return 'PASS'

def generate_rps_key(key: bytes, msg: bytes) -> bytes:
	hash1 = hmac.new(key, msg, sha1).digest()
	hash2 = hmac.new(key, (hash1 + msg), sha1).digest()
	hash3 = hmac.new(key, hash1, sha1).digest()
	hash4 = hmac.new(key, (hash3 + msg), sha1).digest()
	
	return (hash2[:20] + hash4[:4])

def encrypt_with_key_and_iv_tripledes_cbc(key: bytes, iv: bytes, msg: bytes) -> bytes:
	from cryptography.hazmat.primitives.ciphers import Cipher
	from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
	from cryptography.hazmat.primitives.ciphers.modes import CBC
	from cryptography.hazmat.backends import default_backend
	
	tripledes_cbc_cipher = Cipher(TripleDES(key), mode = CBC(iv), backend = default_backend())
	tripledes_cbc_encryptor = tripledes_cbc_cipher.encryptor()
	
	final = tripledes_cbc_encryptor.update(msg)
	final += tripledes_cbc_encryptor.finalize()
	
	return final

def gen_mail_data(user: User, backend: Backend, *, oim: Optional[OIM] = None, just_sent: bool = False, on_ns: bool = True, e_node: bool = True, q_node: bool = True) -> str:
	md_m_pl = ''
	oim_collection = []
	if just_sent:
		if oim is not None:
			oim_collection.append(oim)
	else:
		oim_collection = backend.user_service.get_oim_batch(user)
	if on_ns and len(oim_collection) > 25: return 'too-large'
	
	for oim in oim_collection:
		md_m_pl += M_MAIL_DATA_PAYLOAD.format(
			rt = (RT_M_MAIL_DATA_PAYLOAD.format(
				senttime = date_format(oim.sent)
			) if not just_sent else ''), oimsz = len(format_oim(oim)),
			frommember = oim.from_email, guid = oim.uuid, fid = ('00000000-0000-0000-0000-000000000009' if not just_sent else '.!!OIM'),
			fromfriendly = (_encode_friendly(oim.from_friendly, oim.from_friendly_charset, oim.from_friendly_encoding, space = True if just_sent else False) if oim.from_friendly is not None else ''),
			su = ('<SU> </SU>' if just_sent else ''),
		)
	
	return MAIL_DATA_PAYLOAD.format(
		e = (E_MAIL_DATA_PAYLOAD if e_node else ''),
		q = (Q_MAIL_DATA_PAYLOAD if q_node else ''),
		m = md_m_pl,
	)

def format_oim(oim: OIM) -> str:
	if not oim.headers:
		oim_headers = OIM_HEADER_BASE.format(run_id = '{' + oim.run_id + '}').replace('\n', '\r\n')
	else:
		oim_headers = '\r\n'.join(['{}: {}'.format(name, value) for name, value in oim.headers.items()])
	
	sent_email = oim.sent.astimezone(timezone('US/Pacific'))
	
	if oim.from_friendly is not None:
		friendly = '{} '.format(_encode_friendly(oim.from_friendly, oim.from_friendly_charset, oim.from_friendly_encoding))
	else:
		friendly = None
	oim_msg = OIM_HEADER_PRE_0.format(
		pst1 = sent_email.strftime('%a, %d %b %Y %H:%M:%S -0800'), friendly = friendly or '',
		sender = oim.from_email, recipient = oim.to_email, ip = oim.origin_ip or '',
	).replace('\n', '\r\n')
	if oim.oim_proxy:
		oim_msg += OIM_HEADER_PRE_1.format(oimproxy = oim.oim_proxy).replace('\n', '\r\n')
	oim_msg += oim_headers
	oim_msg += OIM_HEADER_REST.format(
		utc = oim.sent.strftime('%d %b %Y %H:%M:%S.%f')[:25] + ' (UTC)', ft = _datetime_to_filetime(oim.sent),
		pst2 = sent_email.strftime('%d %b %Y %H:%M:%S -0800'),
	).replace('\n', '\r\n')
	
	oim_msg += '\r\n\r\n' + base64.b64encode(oim.message.encode('utf-8')).decode('utf-8')
	
	return oim_msg

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

def _encode_friendly(friendlyname: str, charset: str, encoding: str, *, space: bool = False) -> Optional[str]:
	data_encoded = None
	
	data = friendlyname.encode(charset)
	if encoding is 'B':
		data_encoded = base64.b64encode(data)
	elif encoding is 'Q':
		data_encoded = quopri_encode(data)
	if data_encoded is None:
		return None
	data_encoded_str = data_encoded.decode('utf-8')
	if space:
		data_encoded_str += ' '
	return '=?{}?{}?{}?='.format(charset, encoding, data_encoded_str)

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

OIM_HEADER_PRE_0 = '''X-Message-Info: cwRBnLifKNE8dVZlNj6AiX8142B67OTjG9BFMLMyzuui1H4Xx7m3NQ==
Received: from OIM-SSI02.phx.gbl ([65.54.237.206]) by oim1-f1.hotmail.com with Microsoft SMTPSVC(6.0.3790.211);
	 {pst1}
Received: from mail pickup service by OIM-SSI02.phx.gbl with Microsoft SMTPSVC;
	 {pst1}
From: {friendly}<{sender}>
To: {recipient}
Subject: 
X-OIM-originatingSource: {ip}
'''

OIM_HEADER_PRE_1 = '''X-OIMProxy: {oimproxy}
'''

OIM_HEADER_BASE = '''MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: base64
X-OIM-Message-Type: OfflineMessage
X-OIM-Run-Id: {run_id}'''

OIM_HEADER_REST = '''
Message-ID: <OIM-SSI02zDv60gxapz00061a8b@OIM-SSI02.phx.gbl>
X-OriginalArrivalTime: {utc} FILETIME=[{ft}]
Date: {pst2}
Return-Path: ndr@oim.messenger.msn.com'''

NFY_PUT_PRESENCE = '''Routing: 1.0
To: 1:{to}
From: 1:{from_email}

Reliability: 1.0

Notification: 1.0
NotifNum: 0
Uri: /user
NotifType: Partial
Content-Type: application/user+xml
Content-Length: {cl}

{payload}'''

NFY_PUT_PRESENCE_USER = '<user><s n="IM"><Status>{substatus}</Status>{cm}</s>{rst}</user>'

NFY_PUT_PRESENCE_USER_S_CM = '<CurrentMedia>{cm}</CurrentMedia>'

NFY_PUT_PRESENCE_USER_S_PE = '<s n="PE"><UserTileLocation>{msnobj}</UserTileLocation><FriendlyName>{name}</FriendlyName><PSM>{message}</PSM><DDP>{ddp}</DDP><ColorScheme>{colorscheme}</ColorScheme><Scene>{scene}</Scene><SignatureSound>{sigsound}</SignatureSound></s>'

NFY_PUT_PRESENCE_USER_SEP_IM = '<sep n="IM"{epid_attrib}><Capabilities>{capabilities}</Capabilities></sep>'

NFY_PUT_PRESENCE_USER_SEP_PE = '<sep n="PE"{epid_attrib}>{pe_data}</sep>'

NFY_PUT_PRESENCE_USER_SEP_PE_VER = '<VER>{ver}</VER>'

NFY_PUT_PRESENCE_USER_SEP_PE_TYP = '<TYP>{typ}</TYP>'

NFY_PUT_PRESENCE_USER_SEP_PE_CAP = '<Capabilities>{pe_capabilities}</Capabilities>'

NFY_PUT_PRESENCE_USER_SEP_PD = '<sep n="PD" epid="{mguid}">{ped_data}</sep>'

NFY_PUT_PRESENCE_USER_SEP_EPID = ' epid="{mguid}"'

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
