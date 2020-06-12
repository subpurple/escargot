import base64, struct, hmac
from hashlib import sha1

from front.msn.msnp_ns import MSNPCtrlNS
from front.msn.misc import generate_rps_key, encrypt_with_key_and_iv_tripledes_cbc
from core.models import User

from .mock import ANY

def login_msnp(nc: MSNPCtrlNS, email: str, pop_id: str) -> User:
	w = nc.writer
	
	nc._m_ver('0', 'MSNP18')
	w.pop_message('VER', '0', 'MSNP18')
	nc._m_cvr('1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5')
	w.pop_message('CVR', '1', 'a5', 'a5', 'a5', ANY, ANY)
	nc._m_usr('2', 'SSO', 'I', email)
	w.pop_message('GCF', 0, ANY)
	msg = w.pop_message('USR', '2', 'SSO', 'S', ANY, ANY)
	nonce = msg[5].encode('utf-8')
	
	uuid = nc.backend.user_service.get_uuid(email)
	bsecret = base64.b64encode((b'\x00' * 24)).decode('ascii')
	token, _ = nc.backend.login_auth_service.create_token('nb/login', [uuid, bsecret])
	nc._m_usr('3', 'SSO', 'S', token, _create_rps_response(nonce, bsecret), pop_id)
	w.pop_message('USR', '3', 'OK', email, '1', '0')
	
	bs = nc.bs
	assert bs is not None
	user = bs.user
	
	w.pop_message('SBS', 0, 'null')
	w.pop_message('MSG', 'Hotmail', 'Hotmail', ANY)
	w.pop_message('UBX', '1:' + user.email, b'')
	
	nc._m_adl('4', b'<ml l="1"></ml>')
	w.pop_message('ADL', '4', 'OK')
	nc._m_uux('5', b'<EndpointData><Capabilities>0:0</Capabilities></EndpointData>')
	w.pop_message('UUX', '5', ANY)
	nc._m_uux('6', b'<PrivateEndpointData><EpName>TEST</EpName><Idle>false</Idle><ClientType>1</ClientType><State>NLN</State></PrivateEndpointData>')
	w.pop_message('UUX', '6', ANY)
	w.assert_empty()
	
	return user

def _create_rps_response(nonce: bytes, bs_encoded: str) -> None:
	iv = b'\x00' * 8
	bs = base64.b64decode(bs_encoded)
	
	result = b''
	# TODO: Calculate actual cipher length
	result += struct.pack('<IIIIIII', 28, 1, 0x6603, 0x8004, 8, 20, 72)
	
	key2 = generate_rps_key(bs, b'WS-SecureConversationSESSION KEY HASH')
	key3 = generate_rps_key(bs, b'WS-SecureConversationSESSION KEY ENCRYPTION')
	
	response_hash = hmac.new(key2, nonce, sha1).digest()
	response_cipher = encrypt_with_key_and_iv_tripledes_cbc(key3, iv, nonce)
	
	result += iv + response_hash + response_cipher
	
	return base64.b64encode(result).decode('ascii')
