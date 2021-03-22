from typing import Tuple, Dict, Any, Optional, List
from datetime import datetime
from lxml.etree import fromstring as parse_xml, XMLSyntaxError
import base64
from email.parser import Parser
import secrets
from hashlib import sha384, sha1
from urllib.parse import quote
import hmac
import re
import binascii
import struct
import time

from util.misc import Logger, gen_uuid, date_format, MultiDict
import settings

from core import event, error
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import (
	Substatus, Lst, NetworkID, User, Group, GroupChat, GroupChatRole, GroupChatState,
	Contact, TextWithData, MessageData, MessageType, LoginOption, OIM,
)
from core.client import Client

from .msnp import MSNPCtrl
from .misc import (
	build_presence_notif, cid_format, encode_payload, decode_capabilities_capabilitiesex, decode_email_networkid,
	normalize_pop_id, decode_email_pop, gen_mail_data, gen_signedticket_xml, uuid_to_high_low,
	generate_rps_key, encrypt_with_key_and_iv_tripledes_cbc, Err, MSNStatus, MSNObj,
)

MSNP_DIALECTS = ['MSNP{}'.format(d) for d in (
	# Actually supported
	18, 17, 16, 15, 14, 13, 12, 11,
	10, 9, 8, 7, 6, 5, 4, 3, 2,
	# Not actually supported
	19, 20, 21,
)]

class MSNPCtrlNS(MSNPCtrl):
	__slots__ = (
		'backend', 'dialect', 'usr_email', 'bs', 'client', 'syn_ser', 'gcf_sent', 'syn_sent', 'iln_sent',
		'challenge', 'rps_challenge', 'circle_authenticated', 'new_circles', 'initial_adl_sent', 'circle_adl_sent',
	)
	
	backend: Backend
	dialect: int
	usr_email: Optional[str]
	bs: Optional[BackendSession]
	client: Client
	syn_ser: int
	syn_sent: bool
	gcf_sent: bool
	iln_sent: bool
	challenge: Optional[str]
	rps_challenge: Optional[bytes]
	circle_authenticated: bool
	new_circles: List[GroupChat]
	initial_adl_sent: bool
	circle_adl_sent: bool
	
	def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
		super().__init__(logger)
		self.backend = backend
		self.dialect = 0
		self.usr_email = None
		self.bs = None
		self.client = Client('msn', '?', via)
		self.syn_ser = 0
		self.syn_sent = False
		self.gcf_sent = False
		self.iln_sent = False
		self.challenge = None
		self.rps_challenge = None
		self.circle_authenticated = False
		self.new_circles = []
		self.initial_adl_sent = False
		self.circle_adl_sent = False
	
	def _on_close(self) -> None:
		if self.bs:
			self.bs.close()
	
	def on_connect(self) -> None:
		pass
	
	# State = Auth
	
	def _m_ver(self, trid: str, *args: str) -> None:
		#>>> VER trid MSNPz MSNPy MSNPx [CVR0]
		if self.dialect != 0:
			self.send_reply(Err.NotExpected, trid)
			self.close()
			return
		
		dialects = [a.upper() for a in args]
		try:
			_ = int(trid)
		except ValueError:
			self.close()
		d = None
		for d in MSNP_DIALECTS:
			if d in dialects: break
		if d not in dialects:
			self.send_reply('VER', trid, 0)
			self.close()
			return
		self.client = Client('msn', d, self.client.via)
		self.dialect = int(d[4:])
		self.send_reply('VER', trid, d)
	
	def _m_cvr(self, trid: str, *args: str) -> None:
		v = args[5]
		self.client = Client('msn', v, self.client.via)
		self.send_reply('CVR', trid, v, v, v, 'https://escargot.log1p.xyz', 'https://escargot.log1p.xyz')
	
	def _m_inf(self, trid: str) -> None:
		dialect = self.dialect
		if dialect < 8:
			self.send_reply('INF', trid, 'MD5')
		else:
			self.close()
	
	def _m_usr(self, trid: str, authtype: str, stage: str, *args: str) -> None:
		dialect = self.dialect
		backend = self.backend
		machineguid = None # type: Optional[str]
		
		if authtype == 'SHA':
			if dialect < 18:
				self.close()
				return
			# Used in MSNP18 (at least, for now) to validate Circle tickets
			# found in ABFindContactsPaged responses
			bs = self.bs
			assert bs is not None
			signedticket = args[0]
			if stage == 'A':
				#>>> USR trid SHA A b64_signedticket
				if signedticket != base64.b64encode(gen_signedticket_xml(bs, backend).encode('utf-8')).decode('utf-8'):
					self.circle_authenticated = False
					self.send_reply(Err.AuthFail, trid)
					return
				self.circle_authenticated = True
				self.send_reply('USR', trid, 'OK', self.usr_email, 0, 0)
				
				if self.circle_authenticated:
					for groupchat in self.new_circles:
						self.send_reply('NFY', 'PUT', encode_payload(PAYLOAD_MSG_7,
							email = _encode_email_epid(bs.user.email, bs.front_data.get('msn_pop_id')), chat_id = groupchat.chat_id,
						))
					self.new_circles.clear()
			return
		
		if authtype == 'MD5':
			if dialect >= 8:
				self.close()
				return
			if self.bs:
				self.send_reply(Err.DuplicateSession, trid)
				return
			if stage == 'I':
				#>>> USR trid MD5 I email@example.com
				email = args[0]
				if '@' not in email:
					self.send_reply(Err.AuthFail, trid)
					self.close()
					return
				salt = backend.user_service.msn_get_md5_salt(email)
				if salt is None:
					# Account is not enabled for login via MD5; send `USR S` with Unix time as salt simply to
					# keep MSNP `USR` flow consistent (`USR I` doesn't validate existence of email, but rather
					# whether its format it correct, `USR S` actually does account checks)
					# TODO: Can we pass an informative message to user?
					salt = str(time.time())
				self.usr_email = email
				self.send_reply('USR', trid, authtype, 'S', salt)
				return
			if stage == 'S':
				#>>> USR trid MD5 S md5_hash
				token = None # type: Optional[str]
				if backend.maintenance_mode:
					self.send_reply(Err.InternalServerError, trid)
					self.close()
					return
				
				md5_hash = args[0]
				usr_email = self.usr_email
				assert usr_email is not None
				uuid = backend.user_service.msn_login_md5(usr_email, md5_hash)
				if uuid is not None:
					self.bs = backend.login(uuid, self.client, BackendEventHandler(self), option = LoginOption.BootOthers)
					token, _ = backend.login_auth_service.create_token('nb/login', [uuid, None], lifetime = 86400)
				self._util_usr_final(trid, token or '', None)
				return
		
		if authtype == 'TWN':
			if dialect >= 15 or dialect < 8:
				self.close()
				return
			if self.bs:
				self.send_reply(Err.InvalidUser, trid)
				return
			if stage == 'I':
				#>>> USR trid TWN I email@example.com
				self.usr_email = args[0]
				if '@' not in self.usr_email:
					self.send_reply(Err.AuthFail, trid)
					self.close()
					return
				#extra = ('ct={},rver=5.5.4177.0,wp=FS_40SEC_0_COMPACT,lc=1033,id=507,ru=http://messenger.msn.com,\
				#tw=0,kpp=1,kv=4,ver=2.1.6000.1,rn=1lgjBfIL,tpf=b0735e3a873dfb5e75054465196398e0'.format(int(time())),)
				if dialect >= 13:
					self.send_reply('GCF', 0, SHIELDS_MSNP13)
				self.send_reply('USR', trid, authtype, 'S', 'ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1')
				return
			if stage == 'S':
				#>>> USR trid TWN S auth_token
				if backend.maintenance_mode:
					self.send_reply(Err.InternalServerError, trid)
					self.close()
					return
				
				token = args[0]
				if token[0:2] == 't=':
					token = token[2:22]
				usr_email = self.usr_email
				assert usr_email is not None
				if settings.DEBUG and settings.DEBUG_MSNP: print(F"Token: {token}")
				tpl = backend.login_auth_service.get_token('nb/login', token)
				if tpl is not None:
					uuid = tpl[0]
					assert uuid is not None
					self.bs = backend.login(uuid, self.client, BackendEventHandler(self), option = LoginOption.BootOthers)
				self._util_usr_final(trid, token, None)
				return
		
		if authtype == 'SSO':
			if dialect < 15:
				self.close()
				return
			if self.bs:
				self.send_reply(Err.InvalidUser, trid)
				return
			if stage == 'I':
				#>>> USR trid SSO I email@example.com
				self.usr_email = args[0]
				if '@' not in self.usr_email:
					self.send_reply(Err.AuthFail, trid)
					self.close()
					return
				# https://web.archive.org/web/20100819015007/http://msnpiki.msnfanatic.com/index.php/MSNP15:SSO
				self.rps_challenge = base64.b64encode(secrets.token_bytes(48))
				
				self.send_reply('GCF', 0, SHIELDS_MSNP13)
				self.send_reply('USR', trid, authtype, 'S', 'MBI_KEY_OLD', self.rps_challenge.decode('utf-8'))
				return
			if stage == 'S':
				#>>> USR trid SSO S auth_token [b64_response; not included when MSIDCRL-patched clients login]
				#>>> USR trid SSO S auth_token b64_response machineguid (MSNP >= 16)
				if backend.maintenance_mode:
					self.send_reply(Err.InternalServerError, trid)
					self.close()
					return
				
				token = args[0]
				if token[0:2] == 't=':
					token = token[2:22]
				usr_email = self.usr_email
				assert usr_email is not None
				if settings.DEBUG and settings.DEBUG_MSNP: print(F"Token: {token}")
				tpl = backend.login_auth_service.get_token('nb/login', token)
				option = None
				
				if tpl is not None:
					uuid = tpl[0]
					assert uuid is not None
					
					response = None
					rps = False
					
					if dialect >= 16 or (dialect < 16 and len(args) > 1):
						rps = True
					
					if settings.DEBUG and settings.DEBUG_MSNP: print('RPS authentication:', rps)
					
					if rps:
						assert self.rps_challenge is not None
						
						response_b64 = args[1]
						try:
							response = base64.b64decode(response_b64)
						except:
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						
						if len(response) < 28:
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						
						if struct.unpack('<IIIIII', response[:24]) != (28, 1, 0x6603, 0x8004, 8, 20):
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						response_cipher_len = struct.unpack('<I', response[24:28])[0]
						
						response_payload = response[28:]
						
						if not len(response_payload) == (8+20+response_cipher_len):
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						
						response_iv = response_payload[0:8]
						response_hash = response_payload[8:28]
						response_cipher = response_payload[28:(28+response_cipher_len)]
						
						binarysecret_b64 = tpl[1]
						
						if binarysecret_b64 is None:
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						
						binarysecret = base64.b64decode(binarysecret_b64)
						
						key2 = generate_rps_key(binarysecret, b'WS-SecureConversationSESSION KEY HASH')
						key3 = generate_rps_key(binarysecret, b'WS-SecureConversationSESSION KEY ENCRYPTION')
						
						response_hash_server = hmac.new(key2, self.rps_challenge, sha1).digest()
						
						response_cipher_server = encrypt_with_key_and_iv_tripledes_cbc(key3, response_iv, self.rps_challenge)
						
						if response_hash != response_hash_server or response_cipher != response_cipher_server:
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
					if dialect >= 16:
						machineguid = args[2]
						
						if not re.match(r'^\{?[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}\}?', machineguid):
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
						
						user = backend._load_user_record(uuid)
						if user is not None:
							bses_self = backend.util_get_sessions_by_user(user)
							for bs_self in bses_self:
								pop_id = bs_self.front_data.get('msn_pop_id')
								if pop_id is not None and pop_id.lower() == normalize_pop_id(machineguid).lower():
									option = LoginOption.BootOthers
									break
							if not option:
								option = LoginOption.NotifyOthers
						else:
							self.send_reply(Err.AuthFail, trid)
							self.close()
							return
					else:
						option = LoginOption.BootOthers
					self.bs = backend.login(uuid, self.client, BackendEventHandler(self), option = option)
				self._util_usr_final(trid, token, machineguid)
				return
		
		self.send_reply(Err.AuthFail, trid)
		self.close()
	
	def _util_usr_final(self, trid: str, token: str, machineguid: Optional[str]) -> None:
		from cryptography.hazmat.backends import default_backend
		from cryptography.hazmat.primitives.asymmetric import rsa
		
		bs = self.bs
		dialect = self.dialect
		
		if bs is None or bs.user.email != self.usr_email:
			self.send_reply(Err.AuthFail, trid)
			self.close()
			return
		
		self.backend.util_set_sess_token(bs, token)
		
		bs.front_data['msn'] = True
		
		if dialect >= 16:
			assert machineguid is not None
			bs.front_data['msn_pop_id'] = normalize_pop_id(machineguid).lower()
		
		bs.front_data['msn_circleticket_sig'] = rsa.generate_private_key(
			public_exponent = 65537, key_size = 2048, backend = default_backend(), # type: ignore
		)
		
		user = bs.user
		
		if dialect < 10:
			args = (user.status.name,) # type: Tuple[Any, ...]
		else:
			args = ()
		if dialect >= 6:
			#verified = user.verified
			verified = True
			args += ((1 if verified else 0),)
		if dialect >= 8:
			args += (0,)
		
		self.send_reply('USR', trid, 'OK', user.email, *args)
		
		(high, low) = uuid_to_high_low(user.uuid)
		(ip, port) = self.peername
		now = datetime.utcnow()
		
		if dialect == 21:
			self.send_reply('CHL', 0, '1663122458434562624782678054')
			msg0 = encode_payload(PAYLOAD_MSG_0,
				email_address = user.email,
				endpoint_ID = '{00000000-0000-0000-0000-000000000000}',
				timestamp = now.isoformat()[:19] + 'Z',
			)
			self.send_reply('NFY', 'PUT', msg0)
		else:
			if dialect >= 11:
				self.send_reply('SBS', 0, 'null')
		
		msg1 = encode_payload(PAYLOAD_MSG_1,
			time = int(now.timestamp()), high = high, low = low,
			token = token, ip = ip, port = port,
			mpop = (0 if not machineguid else 1),
		)
		self.send_reply('MSG', 'Hotmail', 'Hotmail', msg1)
		
		if 16 <= dialect < 21:
			# MSNP21 doesn't use this; unsure if 19/20 use it
			
			# https://pastebin.com/gECWthGE
			# ```[01:59:46 DEBUG papyon.transport] <<< NLN NLN 1:andre-stein@hotmail.com '%20André%20Steinn 2688340284:2550273040 %3cmsnobj%20Creator%3d%22andre-stein%40hotmail.com%22%20Size%3d%225390%22%20Type%3d%223%22%20Location%3d%220%22%20Friendly%3d%22AAA%3d%22%20SHA1D%3d%22RZW585t5UbA8LqXWQVoT8nYbOYA%3d%22%20SHA1C%3d%227Ceck6FU1qeOgrWRsRxsFR8yh8g%3d%22%2f%3e```
			# ```[01:59:47 DEBUG papyon.transport] <<< UBX 1:andre-stein@hotmail.com 1300```
			#
			# This seems to suggest data *was* sent in the initial UBX at some point (along with a status right before) - possibly related to MPoP. If we had more info to work with this could be possibly implemented.
			
			if dialect >= 18:
				rst = ('1:' + user.email,) # type: Tuple[str, ...]
			else:
				rst = (user.email, '1')
			self.send_reply('UBX', *rst, b'')
	
	# State = Live
	
	def _m_syn(self, trid: str, *extra: str) -> None:
		bs = self.bs
		dialect = self.dialect
		
		assert bs is not None
		
		user = bs.user
		settings = user.settings
		detail = user.detail
		assert detail is not None
		
		contacts = detail.contacts
		
		self.syn_sent = True
		
		if dialect < 10:
			self.syn_ser = int(extra[0])
			ser = self._ser()
			if dialect < 7:
				self.send_reply('SYN', trid, ser)
				self.send_reply('GTC', trid, ser, settings.get('GTC', 'A'))
				self.send_reply('BLP', trid, ser, settings.get('BLP', 'AL'))
				if dialect >= 5:
					for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
						prp_value = settings.get(prp_setting)
						if prp_value:
							self.send_reply('PRP', ser, prp_setting, prp_value)
				for lst in (Lst.FL, Lst.AL, Lst.BL, Lst.RL):
					cs = [c for c in contacts.values() if c.lists & lst]
					if cs:
						for i, c in enumerate(cs):
							self.send_reply('LST', trid, lst.name, ser, i + 1, len(cs), c.head.email, c.status.name)
							if dialect >= 5:
								for bpr_setting in ('PHH','PHM','PHW','MOB'):
									bpr_value = c.head.settings.get(bpr_setting)
									if bpr_value:
										self.send_reply('BPR', ser, bpr_setting, bpr_value)
					else:
						self.send_reply('LST', trid, lst.name, ser, 0, 0)
			elif dialect == 7:
				self.send_reply('SYN', trid, ser)
				self.send_reply('GTC', trid, ser, settings.get('GTC', 'A'))
				self.send_reply('BLP', trid, ser, settings.get('BLP', 'AL'))
				for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
					prp_value = settings.get(prp_setting)
					if prp_value:
						self.send_reply('PRP', ser, prp_setting, prp_value)
				num_groups = len(detail._groups_by_id.values()) + 1
				self.send_reply('LSG', trid, ser, 1, num_groups, '0', "Other Contacts", 0)
				for i, g in enumerate(detail._groups_by_id.values()):
					self.send_reply('LSG', trid, ser, i + 2, num_groups, g.id, g.name, 0)
				for lst in (Lst.FL, Lst.AL, Lst.BL, Lst.RL):
					cs = [c for c in contacts.values() if c.lists & lst]
					if cs:
						for i, c in enumerate(cs):
							gs = ((','.join([group.id for group in c._groups.copy()]) or '0') if lst == Lst.FL else None)
							self.send_reply('LST', trid, lst.name, ser, i + 1, len(cs), c.head.email, c.status.name or c.head.email, gs)
							for bpr_setting in ('PHH','PHM','PHW','MOB'):
								bpr_value = c.head.settings.get(bpr_setting)
								if bpr_value:
									self.send_reply('BPR', ser, bpr_setting, bpr_value)
					else:
						self.send_reply('LST', trid, lst.name, ser, 0, 0)
			else:
				num_groups = len(detail._groups_by_id.values()) + 1
				self.send_reply('SYN', trid, ser, len(contacts), num_groups)
				self.send_reply('GTC', settings.get('GTC', 'A'))
				self.send_reply('BLP', settings.get('BLP', 'AL'))
				for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
					prp_value = settings.get(prp_setting)
					if prp_value:
						self.send_reply('PRP', prp_setting, prp_value)
				self.send_reply('LSG', '0', "Other Contacts", 0)
				for g in detail._groups_by_id.values():
					self.send_reply('LSG', g.id, g.name, 0)
				for c in contacts.values():
					self.send_reply(
						'LST', c.head.email, c.status.name or c.head.email, int(c.lists),
						','.join([group.id for group in c._groups.copy()]) or '0',
					)
					for bpr_setting in ('PHH','PHM','PHW','MOB'):
						bpr_value = c.head.settings.get(bpr_setting)
						if bpr_value:
							self.send_reply('BPR', bpr_setting, bpr_value)
		elif 10 <= self.dialect <= 12:
			self.send_reply('SYN', trid, TIMESTAMP, TIMESTAMP, len(contacts), len(detail._groups_by_id.values()))
			self.send_reply('GTC', settings.get('GTC', 'A'))
			self.send_reply('BLP', settings.get('BLP', 'AL'))
			self.send_reply('PRP', 'MFN', user.status.name)
			for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
				prp_value = settings.get(prp_setting)
				if prp_value:
					self.send_reply('PRP', prp_setting, prp_value)
			
			for g in detail._groups_by_id.values():
				self.send_reply('LSG', g.name, g.uuid)
			for c in contacts.values():
				lists = c.lists
				if c.pending:
					# Forge `PL` to lists for pending contacts
					lists |= Lst.PL
					if lists & Lst.RL:
						lists &= ~Lst.RL
				self.send_reply('LST', 'N={}'.format(c.head.email), 'F={}'.format(c.status.name or c.head.email), ('C={}'.format(c.head.uuid) if c.lists & Lst.FL else None),
					int(lists), (None if dialect < 12 else '1'), ','.join([group.uuid for group in c._groups.copy()])
				)
				for bpr_setting in ('PHH','PHM','PHW','MOB'):
					bpr_value = c.head.settings.get(bpr_setting)
					if bpr_value:
						self.send_reply('BPR', bpr_setting, bpr_value)
		else:
			self.send_reply(Err.CommandDisabled, trid)
			return
	
	def _m_gcf(self, trid: str, filename: str) -> None:
		if self.dialect < 11:
			self.close()
			return
		if self.dialect < 13 and not self.syn_sent:
			self.send_reply(Err.NotExpected, trid)
			return
		self.send_reply('GCF', trid, filename, SHIELDS)
	
	def _m_png(self) -> None:
		if self.bs is None:
			self.close()
			return
		self.send_reply('QNG', (60 if self.dialect >= 9 else None))
	
	def _m_uux(self, trid: str, data: bytes) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		elm = parse_xml(data.decode('utf-8'))
		
		ed = elm.find('EndpointData')
		if ed:
			capabilities = ed.find('Capabilities').text
			capabilities_lst = decode_capabilities_capabilitiesex(capabilities)
			if capabilities_lst:
				bs.front_data['msn_capabilities'] = capabilities_lst[0] or 0
				bs.front_data['msn_capabilitiesex'] = capabilities_lst[1] or 0
		
		#ped = elm.find('PrivateEndpointData')
		endpoint_name = elm.find('EpName')
		if endpoint_name is not None:
			bs.front_data['msn_epname'] = endpoint_name.text
		idle = elm.find('Idle')
		if idle is not None:
			bs.front_data['msn_endpoint_idle'] = (True if idle.text == 'true' else False)
		client_type = elm.find('ClientType')
		if client_type is not None:
			bs.front_data['msn_client_type'] = client_type.text
		state = elm.find('State')
		if state is not None:
			try:
				bs.front_data['msn_ep_state'] = getattr(MSNStatus, state.text).name
			except:
				self.close()
				return
		
		psm = elm.find('PSM')
		cm = elm.find('CurrentMedia')
		mg = elm.find('MachineGuid')
		if mg is not None and mg.text is not None:
			bs.front_data['msn_machineguid'] = mg.text
		ddp = elm.find('DDP')
		if ddp is not None:
			bs.front_data['msn_msnobj_ddp'] = ddp.text
		sigsound = elm.find('SignatureSound')
		if sigsound is not None:
			bs.front_data['msn_sigsound'] = sigsound.text
		scene = elm.find('Scene')
		if scene is not None:
			bs.front_data['msn_msnobj_scene'] = scene.text
		colorscheme = elm.find('ColorScheme')
		if colorscheme is not None:
			bs.front_data['msn_colorscheme'] = colorscheme.text
		
		bs.me_update({
			'message': ((psm.text or '') if psm is not None else None),
			'media': ((cm.text or '') if cm is not None else None),
			'needs_notify': (True if user.status.substatus is not Substatus.Offline else False),
			'notify_self': (True if self.dialect >= 16 and user.status.substatus is not Substatus.Offline else False),
			'notify_info': True,
		})
		
		self.send_reply('UUX', trid, 0)
	
	def _m_url(self, trid: str, *ignored: str) -> None:
		self.send_reply('URL', trid, '/unused1', '/unused2', 1)
	
	def _m_adg(self, trid: str, name: str, ignored: Optional[str] = None) -> None:
		#>>> ADG 276 New Group
		bs = self.bs
		assert bs is not None
		try:
			group = bs.me_group_add(name)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		self.send_reply('ADG', trid, self._ser(), name, (group.id if self.dialect < 10 else group.uuid), 0)
	
	def _m_rmg(self, trid: str, group_id: str) -> None:
		#>>> RMG 250 00000000-0000-0000-0001-000000000001
		bs = self.bs
		assert bs is not None
		detail = bs.user.detail
		assert detail is not None
		
		g = None # type: Optional[Group]
		
		if group_id == 'New%20Group':
			# Bug: MSN 7.0 sends name instead of id in a particular scenario
			
			for g in detail._groups_by_id.values():
				if g.name != 'New Group': continue
				group_id = (g.id if self.dialect < 10 else g.uuid)
				break
		else:
			if self.dialect < 10:
				g = detail._groups_by_id.get(group_id)
			else:
				g = detail._groups_by_uuid.get(group_id)
			
			if g is None:
				self.send_reply(Err.GroupInvalid, trid)
				return
		
		try:
			bs.me_group_remove(group_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		
		self.send_reply('RMG', trid, self._ser() or 1, group_id)
	
	def _m_reg(self, trid: str, group_id: str, name: str, ignored: Optional[str] = None) -> None:
		#>>> REG 275 00000000-0000-0000-0001-000000000001 newname
		bs = self.bs
		assert bs is not None
		detail = bs.user.detail
		assert detail is not None
		
		if self.dialect < 10:
			g = detail._groups_by_id.get(group_id)
		else:
			g = detail._groups_by_uuid.get(group_id)
		
		if g is None:
			self.send_reply(Err.GroupInvalid, trid)
			return
		
		try:
			bs.me_group_edit(group_id, new_name = name)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		if self.dialect < 10:
			self.send_reply('REG', trid, self._ser(), group_id, name, 0)
		else:
			self.send_reply('REG', trid, 1, name, group_id, 0)
	
	def _m_adl(self, trid: str, data: bytes) -> None:
		if self.dialect < 13:
			self.close()
			return
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		c_nids = [] # type: List[NetworkID]
		chat_id = None
		circle_mode = False
		
		try:
			adl_xml = parse_xml(data.decode('utf-8'))
			l = adl_xml.get('l')
			initial = (l == '1')
			d_els = adl_xml.findall('d')
			for d_el in d_els:
				domains = [] # type: List[str]
				
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close()
					return
				else:
					domain = d_el.get('n')
					if domain in domains or domain is None:
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close()
						return
					domains.append(domain)
			for i, d_el in enumerate(d_els):
				domain = d_el.get('n')
				c_els = d_el.findall('c')
				if i == 0:
					try:
						c_nids = [NetworkID(int(c_el.get('t'))) for c_el in c_els]
						if NetworkID.CIRCLE in c_nids:
							if (
								NetworkID.WINDOWS_LIVE in c_nids or NetworkID.OFFICE_COMMUNICATOR in c_nids
								or NetworkID.TELEPHONE in c_nids or NetworkID.MNI in c_nids
								or NetworkID.SMTP in c_nids or NetworkID.YAHOO in c_nids
							):
								self.send_reply(Err.XXLInvalidPayload, trid)
								self.close()
								return
							if domain == 'live.com':
								d_els_rest = d_els[1:]
								if d_els_rest:
									self.send_reply(Err.XXLInvalidPayload, trid)
									self.close()
									return
								circle_mode = True
					except ValueError:
						self.send_reply(Err.InvalidNetworkID, trid)
						self.close()
						return
				
				if initial and not circle_mode:
					# core handles syncing contact lists; ignore request
					self.send_reply('ADL', trid, 'OK')
					if not self.initial_adl_sent:
						self.initial_adl_sent = True
					return
				
				if circle_mode:
					if not self.circle_authenticated:
						self.send_reply(Err.InvalidCircleMembership, trid)
						return
				for c_el in c_els:
					lsts = None
					
					#if self.dialect == 21:
					#	s_els = c_el.findall('s')
					#	for s_el in s_els:
					#		if s_el is not None and s_el.get('n') == 'IM':
					#			try:
					#				lsts = Lst(int(s_el.get('l')))
					#			except ValueError:
					#				self.send_reply(Err.XXLInvalidPayload, trid)
					#				self.close()
					#				return
					#	if lsts is None: continue
					
					try:
						lsts = Lst(int(c_el.get('l')))
					except ValueError:
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close()
						return
					
					if lsts & (Lst.RL | Lst.PL):
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close()
						return
					
					username = c_el.get('n')
					if circle_mode:
						if username is not None and username.startswith('00000000-0000-0000-0009-'):
							try:
								chat_id = username[-12:]
							except:
								self.send_reply(Err.InvalidCircleMembership, trid)
								return
						else:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
					
					if circle_mode and (self.initial_adl_sent and not self.circle_adl_sent):
						self.circle_adl_sent = True
					
					if circle_mode:
						groupchat = backend.user_service.get_groupchat(chat_id or '')
						if groupchat is None:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
						membership = groupchat.memberships.get(user.uuid)
						if membership is None or (membership is not None and membership.state != GroupChatState.Accepted):
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
					
					if not circle_mode:
						email = '{}@{}'.format(username, domain)
						contact_uuid = backend.util_get_uuid_from_email(email)
						if contact_uuid is None:
							self.send_reply(Err.InvalidUser2, trid)
							return
			
			if circle_mode and self.initial_adl_sent and not self.circle_adl_sent:
				self.circle_adl_sent = True
			
			for d_el in d_els:
				domain = d_el.get('n')
				
				for c_el in c_els:
					ctc = None
					lsts = None
					
					#networkid = NetworkID(int(c_el.get('t')))
					username = c_el.get('n')
					
					#if self.dialect == 21:
					#	s_els = c_el.findall('s')
					#	for s_el in s_els:
					#		if s_el is not None and s_el.get('n') == 'IM':
					#			lsts = Lst(int(s_el.get('l')))
					#	if lsts is None: continue
					
					lsts = Lst(int(c_el.get('l')))
					
					if circle_mode:
						on_unblock = False
						chat_id = username[-12:]
						groupchat = backend.user_service.get_groupchat(chat_id)
						if groupchat is None: continue
						
						if lsts & Lst.FL or lsts & Lst.AL:
							cs = None
							
							if groupchat.memberships[user.uuid].blocking and not lsts & Lst.BL: on_unblock = True
							
							if on_unblock:
								try:
									bs.me_unblock_circle(groupchat)
								except:
									pass
							
							try:
								cs = backend.join_groupchat(chat_id, 'msn', bs, GroupChatEventHandler(self), pop_id = bs.front_data.get('msn_pop_id'))
							except:
								if on_unblock:
									cs = backend.get_groupchat_cs(chat_id, bs)
								pass
							
							if cs is None: continue
							chat = cs.chat
							
							bs.evt.msn_on_notify_circle_ab(chat_id)
							chat.send_participant_joined(cs, initial_join = (on_unblock is False))
						if lsts & Lst.BL:
							try:
								bs.me_block_circle(groupchat)
							except:
								pass
					else:
						email = '{}@{}'.format(username, domain)
						contact_uuid = backend.util_get_uuid_from_email(email)
						
						if contact_uuid is not None:
							try:
								ctc, _ = bs.me_contact_add(contact_uuid, lsts, name = email)
							except error.ListIsFull:
								self.send_reply(Err.ListLimitReached, trid)
								return
							except Exception:
								pass
							
							if lsts & Lst.FL and not initial:
								if ctc is not None:
									bs.evt.on_presence_notification(ctc, False, Substatus.Offline, trid = trid)
		except Exception as ex:
			if isinstance(ex, XMLSyntaxError):
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close()
			else:
				self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
				return
		
		self.send_reply('ADL', trid, 'OK')
	
	def _m_rml(self, trid: str, data: bytes) -> None:
		if self.dialect < 13:
			self.close()
			return
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		d_el = None
		c_nids = [] # type: List[NetworkID]
		circle_mode = False
		
		try:
			rml_xml = parse_xml(data.decode('utf-8'))
			d_els = rml_xml.findall('d')
			for d_el in d_els:
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close()
					return
			
			for d_el in d_els:
				domain = d_el.get('n')
				c_els = d_el.findall('c')
				for c_el in c_els:
					lsts = None
					
					#if self.dialect == 21:
					#	s_els = c_el.findall('s')
					#	for s_el in s_els:
					#		if s_el is not None and s_el.get('n') == 'IM':
					#			try:
					#				lsts = Lst(int(s_el.get('l')))
					#			except ValueError:
					#				self.send_reply(Err.XXLInvalidPayload, trid)
					#				self.close()
					#				return
					#	if lsts is None: continue
					
					try:
						c_nids = [NetworkID(int(c_el.get('t'))) for c_el in c_els]
						if NetworkID.CIRCLE in c_nids:
							if (
								NetworkID.WINDOWS_LIVE in c_nids or NetworkID.OFFICE_COMMUNICATOR in c_nids
								or NetworkID.TELEPHONE in c_nids or NetworkID.MNI in c_nids
								or NetworkID.SMTP in c_nids or NetworkID.YAHOO in c_nids
							):
								self.send_reply(Err.XXLInvalidPayload, trid)
								self.close()
								return
							circle_mode = True
					except ValueError:
						self.send_reply(Err.InvalidNetworkID, trid)
						self.close()
						return
					try:
						lsts = Lst(int(c_el.get('l')))
					except ValueError:
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close()
						return
					
					if lsts & (Lst.RL | Lst.PL):
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close()
						return
					
					username = c_el.get('n')
					
					if circle_mode:
						if username is not None and username.startswith('00000000-0000-0000-0009-'):
							try:
								chat_id = username[-12:]
							except:
								self.send_reply(Err.InvalidCircleMembership, trid)
								return
						else:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
					
					if circle_mode:
						if backend.user_service.get_groupchat(chat_id or '') is None:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
						chat = backend.chat_get('persistent', chat_id)
						if chat is None:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
				
				for c_el in c_els:
					lsts = Lst(int(c_el.get('l')))
					
					if not circle_mode:
						username = c_el.get('n')
						email = '{}@{}'.format(username, domain)
						
						#if self.dialect == 21:
						#	s_els = c_el.findall('s')
						#	for s_el in s_els:
						#		if s_el is not None and s_el.get('n') == 'IM':
						#			lsts = Lst(int(s_el.get('l')))
						#	if lsts is None: continue
						
						contact_uuid = self.backend.util_get_uuid_from_email(email)
						
						if contact_uuid is not None:
							try:
								bs.me_contact_remove(contact_uuid, lsts)
							except Exception:
								pass
		except Exception as ex:
			if isinstance(ex, XMLSyntaxError):
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close()
				return
			else:
				self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
				return
		
		self.send_reply('RML', trid, 'OK')
	
	def _m_adc(self, trid: str, lst_name: str, arg1: str, arg2: Optional[str] = None) -> None:
		if self.dialect < 10:
			self.close()
			return
		if arg1.startswith('N='):
			#>>> ADC 249 BL N=bob1@hotmail.com
			#>>> ADC 278 AL N=foo@hotmail.com
			#>>> ADC 277 FL N=foo@hotmail.com F=foo@hotmail.com
			email = arg1[2:]
			if '@' not in email:
				self.send_reply(Err.InvalidParameter, trid)
				return
			contact_uuid = self.backend.util_get_uuid_from_email(arg1[2:])
			group_id = None
			name = (arg2[2:] if arg2 else None)
		else:
			# Add C= to group
			#>>> ADC 246 FL C=00000000-0000-0000-0002-000000000002 00000000-0000-0000-0001-000000000003
			contact_uuid = arg1[2:]
			group_id = arg2
			name = None
		
		self._add_common(trid, lst_name, contact_uuid, name, group_id)
	
	def _m_add(self, trid: str, lst_name: str, email: str, name: Optional[str] = None, group_id: Optional[str] = None) -> None:
		#>>> ADD 122 FL email name group
		if self.dialect >= 10:
			self.close()
			return
		if '@' not in email:
			self.send_reply(Err.InvalidParameter, trid)
			return
		contact_uuid = self.backend.util_get_uuid_from_email(email)
		self._add_common(trid, lst_name, contact_uuid, name, group_id)
	
	def _add_common(
		self, trid: str, lst_name: str, contact_uuid: Optional[str], name: Optional[str] = None, group_id: Optional[str] = None,
	) -> None:
		dialect = self.dialect
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		send_bpr_info = False
		
		if contact_uuid is None:
			if dialect >= 10:
				self.send_reply(Err.InvalidUser2, trid)
			else:
				self.send_reply(Err.InvalidUser, trid)
			return
		
		ctc_old = detail.contacts.get(contact_uuid)
		ctc_old_lists = None
		
		lst = getattr(Lst, lst_name)
		
		if lst == Lst.RL and (dialect < 11 or (ctc_old is not None and not ctc_old.pending)):
			self.close()
			return
		
		if ctc_old is not None:
			ctc_old_lists = ctc_old.lists
		
		try:
			ctc, ctc_head = bs.me_contact_add(contact_uuid, lst, name = name, group_id = group_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		
		ser = self._ser()
		
		if dialect >= 10:
			if lst == Lst.FL:
				if group_id:
					self.send_reply('ADC', trid, lst_name, 'C={}'.format(ctc_head.uuid), group_id)
				else:
					self.send_reply(
						'ADC', trid, lst_name, 'N={}'.format(ctc_head.email),
						('F={}'.format(ctc.status.name) if ctc.status.name else None), 'C={}'.format(ctc_head.uuid),
					)
			else:
				self.send_reply('ADC', trid, lst_name, 'N={}'.format(ctc_head.email))
		else:
			self.send_reply('ADD', trid, lst_name, ser, ctc_head.email, name, group_id)
		
		if lst == Lst.FL and (ctc_old_lists is not None and not ctc_old_lists & Lst.FL):
			if self.syn_sent and dialect >= 5:
				ctc_detail = ctc_head.detail
				if ctc_detail is not None:
					ctc_me = ctc_detail.contacts.get(user.uuid)
					if ctc_me is not None:
						if ctc_me.lists & Lst.AL:
							send_bpr_info = True
				self.send_reply('BPR', ser, ctc_head.email, 'PHH', ctc_head.settings.get('PHH') if send_bpr_info else None)
				self.send_reply('BPR', ser, ctc_head.email, 'PHW', ctc_head.settings.get('PHW') if send_bpr_info else None)
				self.send_reply('BPR', ser, ctc_head.email, 'PHM', ctc_head.settings.get('PHM') if send_bpr_info else None)
				self.send_reply('BPR', ser, ctc_head.email, 'MOB', ctc_head.settings.get('MOB', 'N') if send_bpr_info else 'N')
			
			bs.evt.on_presence_notification(ctc, False, Substatus.Offline, trid = trid, updated_phone_info = {
				'PHH': ctc_head.settings.get('PHH'),
				'PHW': ctc_head.settings.get('PHW'),
				'PHM': ctc_head.settings.get('PHM'),
				'MOB': ctc_head.settings.get('MOB'),
			})
	
	def _m_rem(self, trid: str, lst_name: str, usr: str, group_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		
		lst = getattr(Lst, lst_name)
		if lst is Lst.RL:
			bs.close()
			return
		if lst is Lst.FL:
			#>>> REM 279 FL 00000000-0000-0000-0002-000000000001
			#>>> REM 247 FL 00000000-0000-0000-0002-000000000002 00000000-0000-0000-0001-000000000002
			if self.dialect < 10:
				contact_uuid = self.backend.util_get_uuid_from_email(usr)
			else:
				if not re.match(r'^[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}', usr):
					self.send_reply(Err.ContactListError, trid)
					return
				contact_uuid = usr
		else:
			#>>> REM 248 AL bob1@hotmail.com
			contact_uuid = self.backend.util_get_uuid_from_email(usr)
		if contact_uuid is None:
			self.send_reply(Err.InvalidUser, trid)
			return
		try:
			bs.me_contact_remove(contact_uuid, lst, group_id = group_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		self.send_reply('REM', trid, lst_name, self._ser(), usr, group_id)
	
	def _m_gtc(self, trid: str, value: str) -> None:
		if self.dialect >= 13:
			self.close()
			return
		# "Alert me when other people add me ..." Y/N
		#>>> GTC 152 N
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if value not in ('A','N'):
			self.close()
			return
		if user.settings.get('GTC') == value:
			self.send_reply(Err.AlreadyInMode, trid)
			return
		bs.me_update({ 'gtc': value })
		self.send_reply('GTC', trid, self._ser(), value)
	
	def _m_blp(self, trid: str, value: str) -> None:
		# Check "Only people on my Allow List ..." AL/BL
		#>>> BLP 143 BL
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if value not in ('AL','BL'):
			self.close()
			return
		if user.settings.get('BLP') == value and self.dialect < 13:
			self.send_reply(Err.AlreadyInMode, trid)
			return
		bs.me_update({ 'blp': value })
		self.send_reply('BLP', trid, self._ser(), value)
	
	def _m_chg(self, trid: str, sts_name: str, capabilities: Optional[str] = None, msnobj: Optional[str] = None) -> None:
		#>>> CHG 120 BSY 1073791020 <msnobj .../>
		dialect = self.dialect
		backend = self.backend
		bs = self.bs
		assert bs is not None
		
		capabilities_msn = None # type: Optional[str]
		capabilities_msn_ex = None # type: Optional[str]
		
		try:
			msn_substatus = MSNStatus.ToSubstatus(getattr(MSNStatus, sts_name))
		except:
			self.close()
			return
		
		if msn_substatus is Substatus.Offline:
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		if dialect >= 8:
			if capabilities is None:
				return
			if dialect >= 16 and capabilities.find(':') > 0:
				capabilities_msn, capabilities_msn_ex = capabilities.split(':', 1)
			else:
				try:
					capabilities_msn = str(int(capabilities))
				except ValueError:
					return
		
		bs.front_data['msn_capabilities'] = capabilities_msn or 0
		bs.front_data['msn_capabilitiesex'] = capabilities_msn_ex or 0
		if msnobj == capabilities:
			bs.front_data['msn_msnobj'] = None
			bs.front_data['msn_msnobj_ddp'] = None
		else:
			bs.front_data['msn_msnobj'] = msnobj
		
		bs.me_update({
			'substatus': msn_substatus,
		})
		
		extra = () # type: Tuple[Any, ...]
		if dialect >= 9:
			extra = (MSNObj(msnobj),)
		
		self.send_reply('CHG', trid, sts_name, capabilities, *extra)
		
		# Send ILNs (and system messages, if any)
		if not self.iln_sent:
			self.iln_sent = True
			user = bs.user
			detail = user.detail
			assert detail is not None
			dialect = self.dialect
			for ctc in detail.contacts.values():
				if ctc.lists & Lst.FL:
					for m in build_presence_notif(trid, None, ctc.head, user, dialect, self.backend, self.iln_sent, True):
						self.send_reply(*m)
			# TODO: There's a weird timeout issue with the challenges on 8.x. Comment out for now
			#if dialect >= 6:
			#	self._send_chl(trid)
			if dialect >= 11:
				msg2 = encode_payload(PAYLOAD_MSG_2,
					ct = 'text/x-msmsgsinitialmdatanotification', md = gen_mail_data(user, backend),
				)
				self.send_reply('MSG', 'Hotmail', 'Hotmail', msg2)
			if self.backend.notify_maintenance:
				bs.evt.on_system_message(1, self.backend.maintenance_mins)
		
		if dialect >= 16:
			bs.me_update({
				'notify_self': True,
				'notify_status': True,
			})
	
	def _m_qry(self, trid: str, client_id: str, response: bytes) -> None:
		#if self.dialect == 21:
		#	self.send_reply('QRY', trid)
		#	return
		#
		#challenge = self.challenge
		#self.challenge = None
		#
		#if client_id not in _QRY_ID_CODES or not challenge:
		#	self.send_reply(Err.ChallengeResponseFailed, trid)
		#	self.close()
		#	return
		#
		#id_key, max_dialect = _QRY_ID_CODES[client_id]
		#
		#if self.dialect > max_dialect:
		#	self.send_reply(Err.ChallengeResponseFailed, trid)
		#	self.close()
		#	return
		#
		#server_response = gen_chal_response(challenge, client_id, id_key, msnp11 = (self.dialect >= 11))
		#
		#if response.decode() != server_response:
		#	self.send_reply(Err.ChallengeResponseFailed, trid)
		#	self.close()
		#	return
		#
		#self.send_reply('QRY', trid)
		
		return
	
	def _m_put(self, trid: str, data: bytes) -> None:
		# `PUT` only used for circles in MSNP18
		
		if self.dialect < 18:
			self.close()
			return
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		chat_id = None
		#presence = False
		
		i = data.index(b'\r\n\r\n') + 4
		headers = Parser().parsestr(data[:i].decode('utf-8'))
		
		to = _split_email_epid(str(headers['To']))
		#from_email = _split_email_epid(str(headers['From']))
		
		if to[1] is NetworkID.CIRCLE:
			if not to[0].endswith('@live.com'):
				self.send_reply(Err.InvalidParameter, trid)
				return
			email_end = to[0].rfind('@live.com')
			circle_id = to[0][:email_end]
			if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
				self.send_reply(Err.InvalidParameter, trid)
				return
			chat_id = circle_id[-12:]
		else:
			return
			#ctc_uuid = backend.util_get_uuid_from_email(to[0])
		
		#if to[0] != user.email:
		#	ctc_uuid = backend.util_get_uuid_from_email(to[0])
		#	if ctc_uuid is None:
		#		return
		#	ctc = detail.contacts.get(ctc_uuid)
		#	if ctc is None:
		#		return
		
		nfy_1_index = data.index(b'\r\n\r\n', i) + 4
		
		#nfy_delivery = data[i:nfy_1_index].decode('utf-8')
		
		# TODO: `PUT` ACK
		
		nfy_actual = data[nfy_1_index:]
		
		payload_index = nfy_actual.index(b'\r\n\r\n') + 4
		nfy_headers = Parser().parsestr(nfy_actual[:payload_index].decode('utf-8'))
		payload = nfy_actual[payload_index:]
		
		if nfy_headers.get('Content-Type') == 'application/circles+xml':
			if not self.circle_adl_sent:
				self.send_reply(Err.InvalidParameter, trid)
				return
			
			if chat_id is None: return
			
			groupchat = backend.user_service.get_groupchat(chat_id)
			if groupchat is None:
				self.send_reply(Err.InvalidParameter, trid)
				return
			chat = backend.chat_get('persistent', chat_id)
			if chat is None: return
			
			elm = parse_xml(payload)
			email_elm = elm.find('roster/user/id')
			if email_elm is not None:
				email = email_elm.text
				if not email.startswith('1:'):
					self.send_reply(Err.InvalidParameter, trid)
					return
				email = email.split('1:', 1)[1]
				if email == user.email:
					cs = backend.get_groupchat_cs(chat_id, bs)
					if cs is None:
						self.send_reply(Err.InvalidParameter, trid)
						return
					cs.chat.send_participant_status_updated(cs, Substatus.Offline, initial = True)
				else:
					self.send_reply(Err.InvalidParameter, trid)
					return
			
			presence_elm = elm.find('props/presence')
			if presence_elm is not None:
				cs = backend.get_groupchat_cs(chat_id, bs)
				if cs is None:
					self.send_reply(Err.InvalidParameter, trid)
					return
				
				psm_elm = presence_elm.find('Data/PSM')
				if psm_elm is not None:
					chat.front_data['msn_circle_psm'] = psm_elm.text
				cm_elm = presence_elm.find('Data/CurrentMedia')
				if cm_elm is not None:
					chat.front_data['msn_circle_cm'] = cm_elm.text
				
				chat.send_update()
		else:
			return
		
		#if headers.get('Content-Type') == 'application/user+xml':
		#	presence = True
		#for other_header in other_headers:
		#	if 'application/user+xml' in other_header:
		#		presence = True
		#
		#if presence:
		#	try:
		#		payload_xml = parse_xml(payload)
		#		
		#		if not (to[1] is NetworkID.WINDOWS_LIVE and to[0] == user.email and to[2] is None):
		#			return
		#		
		#		name = None # type: Optional[str]
		#		psm = None # type: Optional[str]
		#		substatus = None # type: Optional[Substatus]
		#		currentmedia = None # type: Optional[str]
		#		capabilities = None # type: Optional[str]
		#		capabilities_ex = None # type: Optional[str]
		#		pe_capabilities = None # type: Optional[str]
		#		pe_capabilitiesex = None # type: Optional[str]
		#		
		#		#TODO: Better notification flag criteria
		#		
		#		s_els = payload_xml.findall('s')
		#		for s_el in s_els:
		#			if s_el.get('n') == 'IM':
		#				substatus_elm = s_el.find('Status')
		#				if substatus_elm is not None:
		#					try:
		#						substatus = MSNStatus.ToSubstatus(getattr(MSNStatus, substatus_elm.text))
		#					except ValueError:
		#						self.close()
		#						return
		#				currentmedia_elm = s_el.find('CurrentMedia')
		#				if currentmedia_elm is not None:
		#					currentmedia = currentmedia_elm.text
		#			if s_el.get('n') == 'PE':
		#				name_elm = s_el.find('FriendlyName')
		#				if name_elm is not None:
		#					name = name_elm.text
		#				psm_elm = s_el.find('PSM')
		#				if psm_elm is not None:
		#					psm = psm_elm.text
		#				utl_el = s_el.find('UserTileLocation')
		#				if utl_el is not None:
		#					bs.front_data['msn_msnobj'] = utl_el.text
		#				ddp = s_el.find('DDP')
		#				if ddp is not None:
		#					bs.front_data['msn_msnobj_ddp'] = ddp.text
		#				scene = s_el.find('Scene')
		#				if scene is not None:
		#					bs.front_data['msn_msnobj_scene'] = scene.text
		#				colorscheme = s_el.find('ColorScheme')
		#				if colorscheme is not None:
		#					bs.front_data['msn_colorscheme'] = colorscheme.text
		#		sep_elms = payload_xml.findall('sep')
		#		for sep_elm in sep_elms:
		#			if sep_elm.get('n') == 'IM':
		#				capabilities_elm = sep_elm.find('Capabilities')
		#				if capabilities_elm is not None:
		#					if ':' in capabilities_elm.text:
		#						capabilities, capabilitiesex = capabilities_elm.text.split(':', 1)
		#					
		#					try:
		#						if capabilities is not None:
		#							capabilities = str(int(capabilities))
		#						if capabilitiesex is not None:
		#							capabilitiesex = str(int(capabilitiesex))
		#					except ValueError:
		#						self.close()
		#						return
		#					
		#					bs.front_data['msn_capabilities'] = capabilities or 0
		#					bs.front_data['msn_capabilitiesex'] = capabilitiesex or 0
		#			if sep_elm.get('n') == 'PD':
		#				client_type = sep_elm.find('ClientType')
		#				if client_type is not None:
		#					bs.front_data['msn_client_type'] = client_type.text or None
		#				epname = sep_elm.find('EpName')
		#				if epname is not None:
		#					bs.front_data['msn_epname'] = epname.text or None
		#				idle = sep_elm.find('Idle')
		#				if idle is not None:
		#					bs.front_data['msn_endpoint_idle'] = (True if idle.text == 'true' else False)
		#				state = sep_elm.find('State')
		#				if state is not None:
		#					try:
		#						bs.front_data['msn_ep_state'] = getattr(MSNStatus, state.text).name
		#					except:
		#						self.close()
		#						return
		#			if sep_elm.get('n') == 'PE':
		#				bs.front_data['msn_PE'] = True
		#				ver = sep_elm.find('VER')
		#				if ver is not None:
		#					bs.front_data['msn_PE_VER'] = ver.text
		#				typ = sep_elm.find('TYP')
		#				if typ is not None:
		#					bs.front_data['msn_PE_TYP'] = typ.text
		#				pe_capabilities_elm = sep_elm.find('Capabilities')
		#				if pe_capabilities_elm is not None:
		#					if ':' in pe_capabilities_elm.text:
		#						pe_capabilities, pe_capabilitiesex = pe_capabilities_elm.text.split(':', 1)
		#					
		#					try:
		#						if pe_capabilities is not None:
		#							pe_capabilities = str(int(pe_capabilities))
		#						if pe_capabilitiesex is not None:
		#							pe_capabilitiesex = str(int(pe_capabilitiesex))
		#					except ValueError:
		#						self.close()
		#						return
		#					
		#					bs.front_data['msn_PE_capabilities'] = pe_capabilities or 0
		#					bs.front_data['msn_PE_capabilitiesex'] = pe_capabilitiesex or 0
		#		
		#		#TODO: Presence is a bit wonky
		#		bs.me_update({
		#			'name': name or user.email,
		#			'message': psm,
		#			'substatus': substatus,
		#			'media': currentmedia,
		#			'needs_notify': (False if user.status.substatus is Substatus.Offline and substatus is None else True),
		#			'notify_self': True,
		#		})
		#		
		#		if not self.iln_sent:
		#			self.iln_sent = True
		#			for ctc in detail.contacts.values():
		#				for m in build_presence_notif(None, None, ctc.head, user, self.dialect, self.backend, self.iln_sent, True):
		#					self.send_reply(*m)
		#		
		#		self.send_reply('PUT', trid, 'OK', b'')
		#		return
		#	except XMLSyntaxError:
		#		self.close()
		#		return
		#
		self.send_reply('PUT', trid, 'OK', b'')
		
		return
	
	def _m_sdg(self, trid: str, data: bytes) -> None:
		if self.dialect < 18:
			self.close()
			return
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		circle_mode = False
		chat_id = None
		cs = None
		#presence = False
		
		i = data.index(b'\r\n\r\n') + 4
		headers = Parser().parsestr(data[:i].decode('utf-8'))
		
		to = _split_email_sdg(str(headers['To']))
		from_email = _split_email_epid(str(headers['From']))
		
		if from_email != (user.email, NetworkID.WINDOWS_LIVE, bs.front_data.get('msn_pop_id')):
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		if to[1] is NetworkID.CIRCLE:
			circle_mode = True
			if not to[0].endswith('@live.com'): return
			email_end = to[0].rfind('@live.com')
			circle_id = to[0][:email_end]
			if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
				self.send_reply(Err.InvalidParameter, trid)
				return
			chat_id = circle_id[-12:]
		else:
			return
			#ctc_uuid = backend.util_get_uuid_from_email(to[0])
		
		#if to[0] != user.email:
		#	ctc_uuid = backend.util_get_uuid_from_email(to[0])
		#	if ctc_uuid is None:
		#		return
		#	ctc = detail.contacts.get(ctc_uuid)
		#	if ctc is None:
		#		return
		
		if to[2] != 'IM':
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		if circle_mode:
			cs = backend.get_groupchat_cs(chat_id, bs)
		else:
			return
		
		if cs is None:
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		message = messagedata_from_sdg(user, bs.front_data.get('msn_pop_id'), data, i)
		if message is None:
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		cs.send_message_to_everyone(message)
	
	def _m_rea(self, trid: str, email: str, name: str) -> None:
		if self.dialect >= 10:
			self.send_reply(Err.CommandDisabled, trid)
			return
		
		bs = self.bs
		assert bs is not None
		
		if email == bs.user.email:
			bs.me_update({ 'name': name })
		self.send_reply('REA', trid, self._ser(), email, name)
	
	def _m_snd(self, trid: str, email: str, lcid: Optional[str] = None, *rest: Optional[str]) -> None:
		# Send email about how to use MSN. Ignore it for now.
		self.send_reply('SND', trid, 'OK')
	
	def _m_sdc(self, trid: str, email: str, lcid: str, arg4: str, arg5: str, arg6: str, arg7: str, name: str, message: Optional[bytes] = None) -> None:
		# Also sends email about how to use MSN, but with the ability to plug in your display name and a custom message. Ignore too.
		if self.dialect < 5:
			self.close()
			return
		self.send_reply('SDC', trid, 'OK')
	
	def _m_vas(self, trid: str, email: str, arg3: str, arg4: str, data: bytes) -> None:
		# Report user. Don't know how to respond.
		if self.dialect < 18:
			self.close()
			return
		
		return
	
	def _m_prp(self, trid: str, key: str, value: Optional[str] = None, *rest: Optional[str]) -> None:
		#>>> PRP 115 MFN ~~woot~~
		dialect = self.dialect
		if dialect < 5:
			self.close()
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if key == 'MFN':
			if dialect < 10:
				self.send_reply(Err.NotExpected, trid)
				return
			bs.me_update({ 'name': value })
		elif key.startswith('PH'):
			if len(key) > 3:
				self.close()
				return
			elif len(key) < 3:
				self.send_reply(Err.NotExpected, trid)
				return
			
			if key.endswith('H'):
				phone_type = 'home_phone'
			elif key.endswith('W'):
				phone_type = 'work_phone'
			elif key.endswith('M'):
				phone_type = 'mobile_phone'
			else:
				self.send_reply(Err.NotExpected, trid)
				return
			
			if value is not None and len(value) > 95:
				self.close()
				return
			
			bs.me_update({ phone_type: value })
		elif key == 'MOB':
			if user.settings['MBE'] == 'N':
				value = 'N'
			else:
				if value not in ('Y','N'):
					bs.me_update({ 'mob': 'N' })
				else:
					bs.me_update({ 'mob': value })
		elif key == 'MBE':
			if value not in ('Y','N'):
				bs.me_update({ 'mbe': 'N' })
			else:
				bs.me_update({ 'mbe': value })
		# TODO: Save other settings?
		self.send_reply('PRP', trid, self._ser(), key, value)
	
	def _m_sbp(self, trid: str, uuid: str, key: str, value: str) -> None:
		#>>> SBP 153 00000000-0000-0000-0002-000000000002 MFN Bob%201%20New
		# Can be ignored: core handles syncing contact names
		if self.dialect >= 13 or self.dialect < 10:
			self.close()
			return
		self.send_reply('SBP', trid, uuid, key, value)
	
	def _m_xfr(self, trid: str, dest: str) -> None:
		bs = self.bs
		assert bs is not None
		
		if dest != 'SB':
			self.send_reply(Err.InvalidParameter, trid)
			return
		
		if not self.iln_sent or (MSNStatus.FromSubstatus(bs.user.status.substatus) is MSNStatus.HDN and self.dialect < 13):
			self.send_reply(Err.NotAllowedWhileHDN, trid)
			return
		dialect = self.dialect
		token, _ = self.backend.auth_service.create_token('sb/xfr', (bs, dialect), lifetime = 120)
		extra = () # type: Tuple[Any, ...]
		if dialect >= 13:
			extra = ('U', 'messenger.msn.com')
		if dialect >= 14:
			extra += (1,)
		self.send_reply('XFR', trid, dest, settings.TARGET_HOST + ':1864', 'CKI', token, *extra)
	
	def _m_ims(self, trid: str, value: str) -> None:
		#>>> IMS 28 ON/OFF
		# Only used in WebTV clients; toggles whether `RNG`s can be received and `XFR`s can be sent
		bs = self.bs
		assert bs is not None
		if value == 'ON':
			bs.chat_enabled = True
		elif value == 'OFF':
			bs.chat_enabled = False
		else:
			# TODO: Proper response to bad `IMS`?
			self.send_reply(Err.NotExpected, trid)
			return
		
		self.send_reply('IMS', trid, '0', value)
	
	def _m_fqy(self, trid: str, data: bytes) -> None:
		# "Federated query; Query contact's network types"
		# https://web.archive.org/web/20100820020114/http://msnpiki.msnfanatic.com:80/index.php/Command:FQY
		d_els = None
		domain = None
		username = None
		contact_uuid = None
		
		if self.dialect < 14:
			self.close()
			return
		
		try:
			fqy_xml = parse_xml(data.decode('utf-8'))
			d_els = fqy_xml.findall('d')
			if len(d_els) == 1:
				d_el = d_els[0]
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close()
					return
				elif len(d_el.getchildren()) > 1:
					self.send_reply(Err.XXLInvalidPayload, trid)
					self.close()
					return
			else:
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close()
				return
			
			domain = d_el.get('n')
			c_el = d_el.find('c')
			username = c_el.get('n')
			email = '{}@{}'.format(username, domain)
			
			contact_uuid = self.backend.util_get_uuid_from_email(email)
			if contact_uuid is None:
				self.send_reply(Err.InvalidUser2, trid)
				return
		except Exception as ex:
			if isinstance(ex, XMLSyntaxError):
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close()
				return
		
		self.send_reply('FQY', trid, '<ml><d n="{}"><c n="{}" t="1" /></d></ml>'.format(
			domain, username,
		).encode('utf-8'))
	
	def _m_uun(self, trid: str, email: str, type: str, data: Optional[bytes] = None) -> None:
		# "Send sharing invitation or reply to invitation"
		# https://web.archive.org/web/20130926060507/http://msnpiki.msnfanatic.com/index.php/MSNP13:Changes#UUN
		if self.dialect < 13:
			self.close()
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		pop_id_self = None
		
		(email, pop_id) = decode_email_pop(email)
		
		uuid = self.backend.util_get_uuid_from_email(email)
		if uuid is None:
			return
		
		ctc_head = self.backend._load_user_record(uuid)
		if ctc_head is None:
			return
		
		if ctc_head.status.is_offlineish():
			self.send_reply(Err.PrincipalNotOnline, trid)
			return
		
		ctc_detail = self.backend._load_detail(ctc_head)
		assert ctc_detail is not None
		
		ctc_me = ctc_detail.contacts.get(user.uuid)
		if ctc_me is not None:
			if ctc_me.lists & Lst.BL:
				self.send_reply(Err.PrincipalNotOnline, trid)
				return
		else:
			if ctc_head.settings.get('BLP', 'AL') == 'BL':
				self.send_reply(Err.PrincipalNotOnline, trid)
				return
		
		try:
			uun_type = int(type)
		except ValueError:
			return
		
		if uun_type is None: return
		
		pop_id_self = bs.front_data.get('msn_pop_id')
		
		for sess_notify in self.backend.util_get_sessions_by_user(ctc_head):
			#if sess_notify is self: continue
			sess_notify.evt.msn_on_uun_sent(bs.user, uun_type, data, pop_id_sender = pop_id_self, pop_id = pop_id)
		
		self.send_reply('UUN', trid, 'OK')
	
	def _m_uum(self, trid: str, email: str, networkid: str, type: str, data: bytes) -> None:
		# For federated messaging (with Yahoo!); also used in MSNP18+ for OIMs
		
		if self.dialect < 14:
			self.close()
			return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		nid = None # type: Optional[NetworkID]
		
		message = None
		
		if type not in ('1','2','3','4'):
			self.close()
			return
		
		try:
			nid = NetworkID(int(networkid))
		except ValueError:
			self.close()
			return
		
		assert nid is not None
		
		if nid is NetworkID.WINDOWS_LIVE and self.dialect < 18:
			self.close()
			return
		
		if nid is not NetworkID.WINDOWS_LIVE:
			return
		
		if type != '1':
			self.close()
			return
		
		contact_uuid = self.backend.util_get_uuid_from_email(email)
		if contact_uuid is None:
			return
		
		ctc_head = self.backend._load_user_record(contact_uuid or '')
		assert ctc_head is not None
		
		if not ctc_head.status.is_offlineish():
			return
		
		ctc_detail = self.backend._load_detail(ctc_head)
		assert ctc_detail is not None
		
		ctc_me = ctc_detail.contacts.get(user.uuid)
		if ctc_me is not None:
			if ctc_me.lists & Lst.BL:
				return
		else:
			if ctc_head.settings.get('BLP', 'AL') == 'BL':
				return
		
		try:
			message_mime = Parser().parsestr(data.decode('utf-8'))
		except:
			pass
		
		assert message_mime is not None
		
		if message_mime.get('Content-Type') is None or str(message_mime.get('Content-Type')).split(';')[0] != 'text/plain':
			return
		
		if message_mime.get('Dest-Agent') != 'client':
			return
		
		try:
			i = data.index(b'\r\n\r\n') + 4
			message = data[i:].decode('utf-8')
			(ip, _) = self.peername
			
			self.backend.user_service.save_oim(
				bs, ctc_head.uuid, gen_uuid(), ip, message, True, from_friendly = user.status.name, oim_proxy = 'MSNMSGR',
			)
		except:
			return
	
	#def _send_chl(self, trid: str) -> None:
	#	backend = self.backend
	#	
	#	self.challenge = str(secrets.randbelow(89999999999999999999) + 10000000000000000000)
	#	backend.loop.create_task(self._check_qry_sent(trid))
	#	self.send_reply('CHL', 0, self.challenge)
	#
	#async def _check_qry_sent(self, trid: str) -> None:
	#	await asyncio.sleep(50)
	#	
	#	if self.challenge:
	#		self.send_reply(Err.ChallengeResponseFailed, trid)
	#		self.close()
	
	def _ser(self) -> Optional[int]:
		if self.dialect >= 10:
			return None
		self.syn_ser += 1
		return self.syn_ser

class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('ctrl',)
	
	ctrl: MSNPCtrlNS
	
	def __init__(self, ctrl: MSNPCtrlNS) -> None:
		self.ctrl = ctrl
	
	def on_system_message(self, *args: Any, **kwargs: Any) -> None:
		if args[0] == 1 and args[1] < 0: return
		
		data = [
			'MIME-Version: 1.0',
			'Content-Type: application/x-msmsgssystemmessage',
			'',
			'Type: {}'.format(args[0]),
		] + [
			'Arg{}: {}'.format(i+1, a)
			for i, a in enumerate(args[1:])
		]
		self.ctrl.send_reply('MSG', 'Hotmail', 'Hotmail', ('\r\n'.join(data) + '\r\n').encode('utf-8'))
	
	def on_maintenance_boot(self) -> None:
		self.on_close(maintenance = True)
	
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True, send_status_on_bl: bool = False,
		sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		if send_status_on_bl and not update_status: return
		if 5 <= self.ctrl.dialect < 13 and updated_phone_info and self.ctrl.syn_sent:
			for phone_type, value in updated_phone_info.items():
				if value is not None:
					self.ctrl.send_reply('BPR', self.ctrl._ser(), ctc.head.email, phone_type, None if send_status_on_bl else value)
		
		if update_status or update_info_other:
			for m in build_presence_notif(
				trid, old_substatus, ctc.head, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, update_info_other,
				update_status = update_status,
			):
				self.ctrl.send_reply(*m)
			return
	
	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		if update_status or update_info:
			for m in build_presence_notif(
				None, old_substatus, user, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, update_info, self_presence = True,
			):
				self.ctrl.send_reply(*m)
			return
	
	def on_chat_invite(
		self, chat: Chat, inviter: User, *, group_chat: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None:
		if group_chat and self.ctrl.circle_authenticated:
			self.msn_on_notify_ab()
		else:
			extra = () # type: Tuple[Any, ...]
			dialect = self.ctrl.dialect
			if dialect >= 13:
				extra = ('U', 'messenger.hotmail.com')
			if dialect >= 14:
				extra += (1,)
			token, _ = self.ctrl.backend.auth_service.create_token('sb/cal', (self.ctrl.bs, dialect, chat), lifetime = 120)
			self.ctrl.send_reply(
				'RNG', chat.ids['main'], settings.TARGET_HOST + ':1864', 'CKI', token, inviter.email, inviter.status.name, *extra,
			)
	
	def on_declined_chat_invite(self, chat: Chat, group_chat: bool = False) -> None:
		if group_chat and self.ctrl.circle_authenticated:
			self.msn_on_notify_ab()
	
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None:
		email = user.email
		name = (user.status.name or email)
		dialect = self.ctrl.dialect
		bs = self.ctrl.bs
		assert bs is not None
		user_me = bs.user
		detail = user_me.detail
		assert detail is not None
		
		if dialect < 13:
			if dialect < 10:
				bs.me_contact_remove(user.uuid, Lst.PL)
				m: Tuple[Any, ...] = ('ADD', 0, Lst.RL.name, self.ctrl._ser(), email, name)
			else:
				m = ('ADC', 0, Lst.RL.name, 'N={}'.format(email), 'F={}'.format(name))
		else:
			username, domain = email.split('@', 1)
			# According to https://github.com/ifwe/digsby/blob/master/digsby/src/msn/p13/MSNP13Notification.py#L493, `ADL`
			# has an `f` parameter for the friendly name it seems.
			# Also, no `l="1"` in `ml`.
			adl_payload = '<ml><d n="{}"><c n="{}" t="1" l="{}" f="{}" /></d></ml>'.format(
				domain, username, int(Lst.RL), quote(name),
			)
			m = ('ADL', 0, adl_payload.encode('utf-8'))
		self.ctrl.send_reply(*m)
		
		if dialect >= 8:
			self.msn_on_notify_ab()
	
	def on_removed_me(self, user: User) -> None:
		email = user.email
		dialect = self.ctrl.dialect
		bs = self.ctrl.bs
		assert bs is not None
		user_me = bs.user
		detail = user_me.detail
		assert detail is not None
		
		if dialect < 13:
			m: Tuple[Any, ...] = ('REM', 0, Lst.RL.name, self.ctrl._ser(), email)
		else:
			username, domain = email.split('@', 1)
			rml_payload = '<ml><d n="{}"><c n="{}" t="1" l="{}" /></d></ml>'.format(
				domain, username, int(Lst.RL),
			)
			m = ('RML', 0, rml_payload.encode('utf-8'))
		self.ctrl.send_reply(*m)
		
		if dialect >= 8:
			self.msn_on_notify_ab()
	
	def on_contact_request_denied(self, user_added: User, message: Optional[str], *, contact_id: Optional[str] = None) -> None:
		pass
	
	def on_oim_sent(self, oim: 'OIM') -> None:
		assert self.ctrl.bs is not None
		if self.ctrl.iln_sent and self.ctrl.dialect >= 11:
			self.ctrl.send_reply('MSG', 'Hotmail', 'Hotmail', encode_payload(PAYLOAD_MSG_2,
				ct = 'text/x-msmsgsoimnotification', md = gen_mail_data(
					self.ctrl.bs.user, self.ctrl.backend, oim = oim, just_sent = True, e_node = False, q_node = False,
				),
			))
	
	def msn_on_oim_deletion(self, oims_deleted: int) -> None:
		if self.ctrl.iln_sent and self.ctrl.dialect >= 11:
			self.ctrl.send_reply('MSG', 'Hotmail', 'Hotmail', encode_payload(PAYLOAD_MSG_3, oims_deleted = str(oims_deleted)))
	
	def msn_on_uun_sent(
		self, sender: User, type: int, data: Optional[bytes], *,
		pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None,
	) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		
		if ctrl.dialect < 13:
			return
		
		if pop_id is not None and 'msn_pop_id' in bs.front_data:
			pop_id_self = bs.front_data.get('msn_pop_id') or ''
			if normalize_pop_id(pop_id).lower() != pop_id_self.lower(): return
		
		if pop_id_sender is not None and pop_id is not None and ctrl.dialect >= 16:
			email = '{};{}'.format(sender.email, '{' + pop_id_sender + '}')
		else:
			email = sender.email
		
		self.ctrl.send_reply('UBN', email, type, data)
	
	def msn_on_notify_ab(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		id_bits = uuid_to_high_low(user.uuid)
		self.ctrl.send_reply('NOT', encode_payload(PAYLOAD_MSG_4,
			member_low = binascii.hexlify(struct.pack('!I', id_bits[1])).decode('utf-8'),
			member_high = binascii.hexlify(struct.pack('!I', id_bits[0])).decode('utf-8'), email = user.email,
			cid = cid_format(user.uuid, decimal = True), now = date_format(datetime.utcnow()),
		))
	
	def msn_on_notify_circle_ab(self, chat_id: str) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		id_bits = uuid_to_high_low(user.uuid)
		
		self.ctrl.send_reply('NOT', encode_payload(PAYLOAD_MSG_8,
			member_low = binascii.hexlify(struct.pack('!I', id_bits[1])).decode('utf-8'),
			member_high = binascii.hexlify(struct.pack('!I', id_bits[0])).decode('utf-8'), email = user.email,
			chat_id = chat_id,
		))
	
	def on_groupchat_created(self, groupchat: GroupChat) -> None:
		ctrl = self.ctrl
		if ctrl.dialect >= 18:
			ctrl.new_circles.append(groupchat)
			self.msn_on_notify_ab()
	
	def on_groupchat_updated(self, groupchat: GroupChat) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		if self.ctrl.circle_authenticated:
			membership = groupchat.memberships.get(user.uuid)
			assert membership is not None
			self.msn_on_notify_circle_ab(groupchat.chat_id)
	
	def on_left_groupchat(self, groupchat: GroupChat) -> None:
		ctrl = self.ctrl
		if ctrl.dialect >= 18:
			try:
				self.ctrl.new_circles.remove(groupchat)
			except:
				pass
			self.msn_on_notify_ab()
	
	def on_groupchat_invite_revoked(self, chat_id: str) -> None:
		if self.ctrl.circle_authenticated:
			self.msn_on_notify_ab()
	
	def on_accepted_groupchat_invite(self, groupchat: GroupChat) -> None:
		if self.ctrl.circle_authenticated:
			self.ctrl.new_circles.append(groupchat)
			self.msn_on_notify_ab()
	
	def on_groupchat_role_updated(self, chat_id: str, role: GroupChatRole) -> None:
		if self.ctrl.circle_authenticated:
			self.msn_on_notify_ab()
	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		pass
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		# TODO: Pass file transfer message to any chats with Yahoo! user (might be impossible until MSNP21)
		pass
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		if option is LoginOption.BootOthers:
			self.ctrl.send_reply('OUT', 'OTH')
			self.ctrl.close()
		elif option is LoginOption.NotifyOthers:
			if not self.ctrl.dialect >= 16:
				self.ctrl.send_reply('OUT', 'OTH')
				self.ctrl.close()
		else:
			# TODO: What do?
			pass
	
	def on_close(self, *, maintenance: bool = False) -> None:
		bs = self.bs
		assert bs is not None
		
		if maintenance:
			self.ctrl.send_reply('OUT', 'SSD')
		self.ctrl.close()

class GroupChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl', 'cs')
	
	ctrl: MSNPCtrlNS
	cs: ChatSession
	
	def __init__(self, ctrl: MSNPCtrlNS) -> None:
		self.ctrl = ctrl
	
	def on_close(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		chat = self.cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		membership = groupchat.memberships[user.uuid]
		if membership.state == GroupChatState.Empty:
			for cs_other in chat.get_roster():
				self.ctrl.send_reply('NFY', 'DEL', encode_payload(PAYLOAD_MSG_9,
					to_email = user.email, nid = str(int(NetworkID.CIRCLE)), uuid = '00000000-0000-0000-0009-{}'.format(groupchat.chat_id),
					from_email = cs_other.user.email,
				))
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool, initial_join: bool) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		if (cs_other.user.status.substatus is Substatus.Invisible and cs_other.user is user) or not cs_other.user.status.is_offlineish():
			if cs_other.user.uuid == groupchat.owner_uuid:
				for m in build_presence_notif(
					None, Substatus.Offline, cs_other.user, user, self.ctrl.dialect, self.ctrl.backend,
					self.ctrl.iln_sent, False, groupchat = groupchat, groupchat_owner = True,
				):
					self.ctrl.send_reply(*m)
			
			for m in build_presence_notif(
				None, Substatus.Offline, cs_other.user, user, self.ctrl.dialect, self.ctrl.backend,
				self.ctrl.iln_sent, True, groupchat = groupchat,
			):
				self.ctrl.send_reply(*m)
		
		if not first_pop: return
		
		self.on_chat_roster_updated()
	
	def on_participant_left(self, cs_other: ChatSession, last_pop: bool) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		if last_pop:
			membership = groupchat.memberships[cs_other.user.uuid]
			if membership.state == GroupChatState.Empty:
				self.ctrl.send_reply('NFY', 'DEL', encode_payload(PAYLOAD_MSG_9,
					to_email = user.email, nid = str(int(NetworkID.CIRCLE)), uuid = '00000000-0000-0000-0009-{}'.format(groupchat.chat_id),
					from_email = cs_other.user.email,
				))
	
	def on_chat_invite_declined(
		self, chat: Chat, invitee: User, *, invitee_id: Optional[str] = None,
		message: Optional[str] = None, group_chat: bool = False,
	) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		
		if group_chat and self.ctrl.circle_authenticated:
			groupchat = chat.groupchat
			assert groupchat is not None
			self.on_chat_roster_updated()
			bs.evt.msn_on_notify_circle_ab(groupchat.chat_id)
	
	def on_chat_updated(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		chat = self.cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		presence = CIRCLE_PROPS.format(
			friendly = groupchat.name, psm = chat.front_data.get('msn_circle_psm') or '', cm = chat.front_data.get('msn_circle_cm') or '',
		)
		
		result = CIRCLE.format(presence)
		
		self.ctrl.send_reply('NFY', 'PUT', encode_payload(PAYLOAD_MSG_6,
			email = _encode_email_epid(user.email, bs.front_data.get('msn_pop_id')), chat_id = groupchat.chat_id,
			cl = len(result), payload = result,
		))
	
	def on_chat_roster_updated(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		users = _get_circle_roster(chat, cs)
			
		roster = CIRCLE_ROSTER.format(users = users)
		
		result = CIRCLE.format(roster)
		
		self.ctrl.send_reply('NFY', 'PUT', encode_payload(PAYLOAD_MSG_5,
			email = user.email, chat_id = groupchat.chat_id,
			cl = len(result), payload = result,
		))
	
	def on_participant_status_updated(self, cs_other: ChatSession, first_pop: bool, initial: bool, old_substatus: Substatus) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		membership = groupchat.memberships[cs_other.user.uuid]
		if membership.state == GroupChatState.Empty: return
		
		if not (initial and cs_other.user.status.is_offlineish()):
			for m in build_presence_notif(
				None, old_substatus, cs_other.user, user, self.ctrl.dialect,
				self.ctrl.backend, self.ctrl.iln_sent, True, groupchat = groupchat,
			):
				self.ctrl.send_reply(*m)
		
		if not cs_other.user.status.is_offlineish():
			self.on_chat_roster_updated()
	
	def on_invite_declined(self, invited_user: User, *, invited_id: Optional[str] = None, message: str = '') -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		if data.sender is bs.user and data.sender_pop_id == bs.front_data.get('msn_pop_id'): return
		
		if data.type is not MessageType.TypingDone:
			self.ctrl.send_reply('SDG', 0, messagedata_to_sdg(data, user, groupchat = groupchat))

def _get_circle_roster(chat: Chat, cs: ChatSession) -> str:
	users = ''
	groupchat = chat.groupchat
	assert groupchat is not None
	
	for cs1 in chat.get_roster_single():
		if (cs1.user.status.is_offlineish() or groupchat.memberships[cs1.user.uuid].blocking) and cs1.user is not cs.user: continue
		users += CIRCLE_USER.format(email = cs1.user.email)
	
	return users

def _split_email_epid(email: str) -> Tuple[str, NetworkID, Optional[str]]:
	epid = None # type: Optional[str]
	
	email_epid = email.split(';', 1)
	networkid, email = decode_email_networkid(email_epid[0])
	if len(email_epid) > 1:
		if email_epid[1].startswith('epid='):
			epid = normalize_pop_id(email_epid[1][5:])
	return (email, networkid, epid)

def _split_email_sdg(email: str) -> Tuple[str, NetworkID, Optional[str]]:
	sdg_path = None # type: Optional[str]
	
	email_path = email.split(';', 1)
	networkid, email = decode_email_networkid(email_path[0])
	if len(email_path) > 1:
		if email_path[1].startswith('path='):
			sdg_path = email_path[1][5:]
	return (email, networkid, sdg_path)

def _encode_email_epid(email: str, pop_id: Optional[str]) -> str:
	result = email
	
	if pop_id:
		result = '{};epid={}'.format(result, '{' + pop_id + '}')
	
	return result

def messagedata_from_sdg(sender: User, sender_pop_id: Optional[str], data: bytes, i: int) -> Optional[MessageData]:
	j = data.index(b'\r\n\r\n', i) + 4
	sdg_messaging = data[j:]
	
	n = sdg_messaging.index(b'\r\n\r\n') + 4
	headers = Parser().parsestr(sdg_messaging[:n].decode('utf-8'))
	body_raw = data[n:]
	
	content_length = headers.get('Content-Length')
	if content_length is None: return None
	try:
		message_length = int(str(content_length))
	except:
		return None
	
	if len(body_raw) < message_length: return None
	body_raw = body_raw[:message_length]
	
	message_type = headers.get('Message-Type')
	message_subtype = headers.get('Message-Subtype')
	if message_subtype is not None:
		message_subtype = str(message_subtype)
	
	try:
		if message_type is not None:
			message_type = str(message_type)
			
			if message_type == 'Text':
				type = MessageType.Chat
				text = body_raw.decode('utf-8')
			elif message_type == 'Nudge':
				type = MessageType.Nudge
				text = ''
			elif message_type == 'Control':
				if message_subtype == 'Typing':
					type = MessageType.Typing
					text = ''
				else:
					type = MessageType.Chat
					text = "(Unsupported MSNP Content-Type)"
			else:
				type = MessageType.Chat
				text = "(Unsupported MSNP Content-Type)"
		else:
			type = MessageType.Chat
			text = "(Unsupported MSNP Content-Type)"
	except:
		type = MessageType.Chat
		text = "(Unsupported MSNP Content-Type)"
	
	message = MessageData(sender = sender, sender_pop_id = sender_pop_id, type = type, text = text)
	message.front_cache['msnp_sdg'] = data
	return message

def messagedata_to_sdg(data: MessageData, user: User, *, groupchat: Optional[GroupChat] = None) -> bytes:
	if 'msnp_sdg' not in data.front_cache:
		s = None
		
		if data.type is MessageType.Typing:
			s = F'Content-Length: 2\r\nContent-Type: text/x-msmsgscontrol\r\nContent-Transfer-Encoding: 7bit\r\n\
Message-Type: Control\r\nMessage-Subtype: Typing\r\nMIME-Version: 1.0\r\nTypingUser: {data.sender.email}\r\n\r\n\r\n'
		elif data.type is MessageType.Nudge:
			s = 'Content-Length: 9\r\nContent-Type: Text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 7bit\r\n\
Message-Type: Nudge\r\nMIME-Version: 1.0\r\n\r\nID: 1\r\n\r\n'
		elif data.type is MessageType.Chat:
			s = 'Content-Length: ' + str(len(data.text or '')) + '\r\nContent-Type: Text/plain; charset=UTF-8\r\n\
Content-Transfer-Encoding: 7bit\r\nMessage-Type: Text\r\nMIME-Version: 1.0\r\n\r\n' + (data.text or '')
		else:
			raise ValueError("unknown message type", data.type)
		
		pre = (
			'Routing: 1.0\r\nTo: '
			+ (
				'9:00000000-0000-0000-0009-{}@live.com;path=IM'.format(groupchat.chat_id) if groupchat is not None else user.email
			)
			+ '\r\nFrom: 1:' + _encode_email_epid(data.sender.email, data.sender_pop_id) + '\r\n\r\n'
		)
		
		r = 'Reliability: 1.0'
		if groupchat is not None:
			r += '\r\nStream: 0\r\nSegment: 0'
		r += '\r\n\r\n'
		if groupchat is not None:
			r += 'Messaging: 1.0\r\n'
		else:
			r += 'Messaging: 2.0\r\n'
		
		data.front_cache['msnp_sdg'] = pre.encode('utf-8') + r.encode('utf-8') + s.encode('utf-8')
	
	return data.front_cache['msnp_sdg']

PAYLOAD_MSG_0 = '''Routing: 1.0
To: 1:{email_address};epid={endpoint_ID}
From: 1:{email_address}

Reliability: 1.0

Notification: 1.0
NotifNum: 0
Uri: /user
NotifType: Partial
Content-Type: application/user+xml
Content-Length: 53

<user><s n="PF" ts="{timestamp}"></s></user>'''

PAYLOAD_MSG_1 = '''MIME-Version: 1.0
Content-Type: text/x-msmsgsprofile; charset=UTF-8
LoginTime: {time}
EmailEnabled: 0
MemberIdHigh: {high}
MemberIdLow: {low}
lang_preference: 1033
preferredEmail:
country:
PostalCode:
Gender:
Kid: 0
Age:
BDayPre:
Birthday:
Wallet:
Flags: 536872513
sid: 507
MSPAuth: {token}Y6+H31sTUOFkqjNTDYqAAFLr5Ote7BMrMnUIzpg860jh084QMgs5djRQLLQP0TVOFkKdWDwAJdEWcfsI9YL8otN9kSfhTaPHR1njHmG0H98O2NE/Ck6zrog3UJFmYlCnHidZk1g3AzUNVXmjZoyMSyVvoHLjQSzoGRpgHg3hHdi7zrFhcYKWD8XeNYdoz9wfA2YAAAgZIgF9kFvsy2AC0Fl/ezc/fSo6YgB9TwmXyoK0wm0F9nz5EfhHQLu2xxgsvMOiXUSFSpN1cZaNzEk/KGVa3Z33Mcu0qJqvXoLyv2VjQyI0VLH6YlW5E+GMwWcQurXB9hT/DnddM5Ggzk3nX8uMSV4kV+AgF1EWpiCdLViRI6DmwwYDtUJU6W6wQXsfyTm6CNMv0eE0wFXmZvoKaL24fggkp99dX+m1vgMQJ39JblVH9cmnnkBQcKkV8lnQJ003fd6iIFzGpgPBW5Z3T1Bp7uzSGMWnHmrEw8eOpKC5ny4x8uoViXDmA2UId23xYSoJ/GQrMjqB+NslqnuVsOBE1oWpNrmfSKhGU1X0kR4Eves56t5i5n3XU+7ne0MkcUzlrMi89n2j8aouf0zeuD7o+ngqvfRCsOqjaU71XWtuD4ogu2X7/Ajtwkxg/UJDFGAnCxFTTd4dqrrEpKyMK8eWBMaartFxwwrH39HMpx1T9JgknJ1hFWELzG8b302sKy64nCseOTGaZrdH63pjGkT7vzyIxVH/b+yJwDRmy/PlLz7fmUj6zpTBNmCtl1EGFOEFdtI2R04EprIkLXbtpoIPA7m0TPZURpnWufCSsDtD91ChxR8j/FnQ/gOOyKg/EJrTcHvM1e50PMRmoRZGlltBRRwBV+ArPO64On6zygr5zud5o/aADF1laBjkuYkjvUVsXwgnaIKbTLN2+sr/WjogxT1Yins79jPa1+3dDenxZtE/rHA/6qsdJmo5BJZqNYQUFrnpkU428LryMnBaNp2BW51JRsWXPAA7yCi0wDlHzEDxpqaOnhI4Ol87ra+VAg==&p=
ClientIP: {ip}
ClientPort: {port}
ABCHMigrated: 1
MPOPEnabled: {mpop}

'''

# OIMs
PAYLOAD_MSG_2 = '''MIME-Version: 1.0
Content-Type: {ct}; charset=UTF-8

Mail-Data: {md}
'''

PAYLOAD_MSG_3 = '''MIME-Version: 1.0
Content-Type: text/x-msmsgsactivemailnotification; charset=UTF-8

Src-Folder: .!!OIM
Dest-Folder: .!!trAsH
Message-Delta: {oims_deleted}
'''

PAYLOAD_MSG_4 = '''<NOTIFICATION id="0" siteid="45705" siteurl="http://contacts.msn.com">
	<TO pid="0x{member_low}:0x{member_high}" name="{email}">
		<VIA agent="messenger" />
	</TO>
	<MSG id="0">
		<SUBSCR url="s.htm" />
		<ACTION url="a.htm" />
		<BODY>
			&lt;NotificationData xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"&gt;
				&lt;Service&gt;ABCHInternal&lt;/Service&gt;
				&lt;CID&gt;{cid}&lt;/CID&gt;
				&lt;LastModifiedDate&gt;{now}&lt;/LastModifiedDate&gt;
				&lt;HasNewItem&gt;false&lt;/HasNewItem&gt;
			&lt;/NotificationData&gt;
		</BODY>
	</MSG>
</NOTIFICATION>'''

PAYLOAD_MSG_5 = '''Routing: 1.0
To: 1:{email}
From: 9:00000000-0000-0000-0009-{chat_id}@live.com

Reliability: 1.0
Stream: 0

Publication: 1.0
Uri: /circle
NotifType: Partial
Content-Type: application/circles+xml
Content-Length: {cl}

{payload}'''

PAYLOAD_MSG_6 = '''Routing: 1.0
To: 1:{email}
From: 9:00000000-0000-0000-0009-{chat_id}@live.com

Reliability: 1.0
Stream: 1
Segment: 0

Publication: 1.0
Uri: /circle
NotifType: Full
Content-Type: application/circles+xml
Content-Length: {cl}

{payload}'''

PAYLOAD_MSG_7 = '''Routing: 1.0
To: 1:{email}
From: 9:00000000-0000-0000-0009-{chat_id}@live.com

Reliability: 1.0
Stream: 0

Notification: 1.0
NotifNum: 0
Uri: /circle
NotifType: Full
Content-Type: application/circles+xml
Content-Length: 0

'''

PAYLOAD_MSG_8 = '''<NOTIFICATION id="0" siteid="45705" siteurl="http://contacts.msn.com">
	<TO pid="0x{member_low}:0x{member_high}" name="{email}">
		<VIA agent="messenger" />
	</TO>
	<MSG id="0">
		<SUBSCR url="s.htm" />
		<ACTION url="a.htm" />
		<BODY>
			&lt;NotificationData xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"&gt;
				&lt;HasNewItem&gt;true&lt;/HasNewItem&gt;
				&lt;CircleId&gt;00000000-0000-0000-0009-{chat_id}&lt;/CircleId&gt;
			&lt;/NotificationData&gt;
		</BODY>
	</MSG>
</NOTIFICATION>'''

PAYLOAD_MSG_9 = '''Routing: 1.0
To: 1:{to_email}
From: {nid}:{uuid}@live.com

Reliability: 1.0
Stream: 0

Notification: 1.0
NotifNum: 2
Uri: /circle/roster(IM)/user(1:{from_email})
NotifType: Partial
Content-Type: application/circles+xml
Content-Length: 0

'''

SHIELDS = '''<?xml version="1.0" encoding="utf-8" ?>
<config>
	<shield><cli maj="7" min="0" minbld="0" maxbld="9999" deny=" " /></shield>
	<block></block>
</config>'''.encode('utf-8')
SHIELDS_MSNP13 = '''<Policies>
	<Policy type="SHIELDS" checksum="D9705A71BA841CB38955822E048970C3"><config> <shield>\
<cli maj="7" min="0" minbld="0" maxbld="9999" deny=" " /></shield> <block></block></config></Policy>
	<Policy type="ABCH" checksum="03DC55910A9CB79133F1576221A80346"><policy><set id="push" service="ABCH" priority="200">\
      <r id="pushstorage" threshold="180000" />    </set><set id="delaysup" service="ABCH" priority="150">\
  <r id="whatsnew" threshold="1800000" />  <r id="whatsnew_storage_ABCH_delay" timer="1800000" />\
  <r id="whatsnewt_link" threshold="900000" trigger="QueryActivities" /></set>  <c id="PROFILE_Rampup">100</c></policy></Policy>
	<Policy type="ERRORRESPONSETABLE" checksum="6127EEDCE860F45C1692896F5248AF6F"><Policy> <Feature type="3" name="P2P">\
  <Entry hr="0x81000398" action="3"/>  <Entry hr="0x82000020" action="3"/> </Feature> <Feature type="4">\
  <Entry hr="0x81000440" /> </Feature> <Feature type="6" name="TURN">  <Entry hr="0x8007274C" action="3" />\
  <Entry hr="0x82000020" action="3" />  <Entry hr="0x8007274A" action="3" /> </Feature></Policy></Policy>
	<Policy type="P2P" checksum="815D4F1FF8E39A85F1F97C4B16C45177"><ObjStr SndDly="1" /></Policy>
</Policies>'''.encode('utf-8')
CIRCLE_ROSTER = '<roster><id>IM</id>{users}</roster>'
CIRCLE_USER = '<user><id>1:{email}</id></user>'

CIRCLE = '<circle>{}</circle>'
CIRCLE_PROPS = '<props><presence dtype="xml"><Data><UTL></UTL><MFN>{friendly}</MFN><PSM>{psm}</PSM>\
<CurrentMedia>{cm}</CurrentMedia></Data></presence></props>'
TIMESTAMP = '2000-01-01T00:00:00.0-00:00'

#_QRY_ID_CODES = {
#	# MSNP6 - 9
#	'msmsgs@msnmsgr.com': ('Q1P7W2E4J9R8U3S5', 10),
#	'PROD0038W!61ZTF9': ('VT6PX?UQTM4WM%YR', 10),
#	'PROD0058#7IL2{QD': ('QHDCY@7R1TB6W?5B', 10),
#	'PROD0061VRRZH@4F': ('JXQ6J@TUOGYV@N0M', 10),
#	'PROD00504RLUG%WL': ('I2EBK%PYNLZL5_J4', 10),
#	'PROD0076ENE8*@AW': ('CEQJ8}OE0!WTSWII', 10),
#	#'PROD00517IFH4@RV': ('<unknown>', 10),
#	# MSNP11 - 12
#	'PROD0090YUAUV{2B': ('YMM8C_H7KCQ2S_KL', 12),
#	'PROD0101{0RM?UBW': ('CFHUR$52U_{VIX5T', 12),
#	# MSNP13 - 14
#	'PROD01065C%ZFN6F': ('O4BG@C7BWLYQX?5G', 14),
#	'PROD0112J1LW7%NB': ('RH96F{PHI8PPX_TJ', 14),
#	# MSNP15+
#	'PROD0113H11T8$X_': ('RG@XY*28Q5QHS%Q5', 21),
#	'PROD0114ES4Z%Q5W': ('PK}_A_0N_K%O?A9S', 21),
#	'PROD0118R6%2WYOS': ('YIXPX@5I2P0UT*LK', 21),
#	'PROD0119GSJUC$18': ('ILTXC!4IXB5FB*PX', 21),
#	# Thanks J.M. for making the tweet with this WLM 2009 ID-key combo. ^_^
#	'PROD0120PW!CCV9@': ('C1BX{V4W}Q3*10SM', 21),
#}
