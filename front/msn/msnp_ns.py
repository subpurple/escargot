from typing import Tuple, Dict, Any, Optional, List
from datetime import datetime
from lxml.etree import fromstring as parse_xml, XMLSyntaxError
import base64
from email.parser import Parser
from email.message import EmailMessage
import secrets
from hashlib import sha384, sha1
import hmac
import asyncio
import re
import binascii
import struct

from util.misc import Logger, gen_uuid, first_in_iterable, arbitrary_decode, date_format, MultiDict
import settings

from core import event
from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import Substatus, Lst, NetworkID, User, OIM, GroupChat, GroupChatRole, Contact, TextWithData, MessageData, MessageType, LoginOption
from core.client import Client

from .msnp import MSNPCtrl
from .misc import build_presence_notif, cid_format, encode_msnobj, encode_payload, decode_capabilities_capabilitiesex, decode_email_networkid, encode_email_networkid, decode_email_pop, gen_mail_data, gen_chal_response, generate_rps_key, encrypt_with_key_and_iv_tripledes_cbc, Err, MSNStatus

MSNP_DIALECTS = ['MSNP{}'.format(d) for d in (
	# Actually supported
	18, 17, 16, 15, 14, 13, 12, 11,
	10, 9, 8, 7, 6, 5, 4, 3, 2,
	# Not actually supported
	19, 20, 21,
)]

class MSNPCtrlNS(MSNPCtrl):
	__slots__ = ('backend', 'dialect', 'usr_email', 'bs', 'client', 'syn_ser', 'gcf_sent', 'syn_sent', 'iln_sent', 'challenge', 'rps_challenge', 'circle_presence', 'initial_adl_sent', 'circle_adl_sent')
	
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
	circle_presence: bool
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
		self.circle_presence = False
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
		dialects = [a.upper() for a in args]
		try:
			t = int(trid)
		except ValueError:
			self.close(hard = True)
		d = None
		for d in MSNP_DIALECTS:
			if d in dialects: break
		if d not in dialects:
			self.send_reply('VER', trid, 0)
			self.close(hard = True)
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
			self.send_reply(Err.CommandDisabled, trid)
	
	def _m_usr(self, trid: str, authtype: str, stage: str, *args: str) -> None:
		dialect = self.dialect
		backend = self.backend
		machineguid = None # type: Optional[str]
		
		if authtype == 'SHA':
			if dialect < 18:
				self.close(hard = True)
				return
			# Used in MSNP18 (at least, for now) to validate Circle tickets
			# found in ABFindContactsPaged responses
			bs = self.bs
			assert bs is not None
			signedticket = args[0]
			if stage == 'A':
				#>>> USR trid SHA A b64_signedticket
				#if signedticket != base64.b64encode(gen_signedticket_xml(bs.user, backend).encode('utf-8')).decode('ascii'):
				#	self.send_reply(Err.AuthFail, trid)
				#	return
				self.send_reply('USR', trid, 'OK', self.usr_email, 0, 0)
			return
		
		if authtype == 'MD5':
			if dialect >= 8:
				self.send_reply(Err.CommandDisabled, trid)
				return
			if self.bs:
				self.send_reply(Err.InvalidUser, trid)
				return
			if stage == 'I':
				#>>> USR trid MD5 I email@example.com
				if backend.maintenance_mode:
					self.send_reply(Err.InternalServerError, trid)
					self.close(hard = True)
					return
				email = args[0]
				salt = backend.user_service.msn_get_md5_salt(email)
				if salt is None:
					# Account is not enabled for login via MD5
					# TODO: Can we pass an informative message to user?
					self.send_reply(Err.AuthFail, trid)
					self.close(hard = True)
					return
				self.usr_email = email
				self.send_reply('USR', trid, authtype, 'S', salt)
				return
			if stage == 'S':
				#>>> USR trid MD5 I md5_hash
				token = None # type: Optional[str]
				md5_hash = args[0]
				usr_email = self.usr_email
				assert usr_email is not None
				uuid = backend.user_service.msn_login_md5(usr_email, md5_hash)
				if uuid is not None:
					self.bs = backend.login(uuid, self.client, BackendEventHandler(self), option = LoginOption.BootOthers)
					token = backend.auth_service.create_token('nb/login', uuid, lifetime = 86400)
				self._util_usr_final(trid, token or '', None)
				return
		
		if authtype in ('TWN', 'SSO'):
			if self.bs:
				self.send_reply(Err.InvalidUser, trid)
				return
			if stage == 'I':
				#>>> USR trid TWN/SSO I email@example.com
				if backend.maintenance_mode:
					self.send_reply(Err.InternalServerError, trid)
					self.close(hard = True)
					return
				self.usr_email = args[0]
				uuid = backend.util_get_uuid_from_email(self.usr_email)
				if uuid is None:
					self.send_reply(Err.AuthFail, trid)
					self.close(hard = True)
					return
				if authtype == 'TWN':
					#extra = ('ct={},rver=5.5.4177.0,wp=FS_40SEC_0_COMPACT,lc=1033,id=507,ru=http:%2F%2Fmessenger.msn.com,tw=0,kpp=1,kv=4,ver=2.1.6000.1,rn=1lgjBfIL,tpf=b0735e3a873dfb5e75054465196398e0'.format(int(time())),)
					# This seems to work too:
					extra = ('ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1',) # type: Tuple[Any, ...]
				else:
					# https://web.archive.org/web/20100819015007/http://msnpiki.msnfanatic.com/index.php/MSNP15:SSO
					self.rps_challenge = base64.b64encode(sha384(secrets.token_bytes(128)).digest())
					extra = ('MBI_KEY_OLD', self.rps_challenge.decode('utf-8'))
				if dialect >= 13:
					self.send_reply('GCF', 0, SHIELDS_MSNP13)
				self.send_reply('USR', trid, authtype, 'S', *extra)
				return
			if stage == 'S':
				#>>> USR trid TWN S auth_token
				#>>> USR trid SSO S auth_token [b64_response; not included when MSIDCRL-patched clients login]
				#>>> USR trid SSO S auth_token [b64_response; not included when MSIDCRL-patched clients login] machineguid (MSNP >= 16)
				token = args[0]
				if token[0:2] == 't=':
					token = token[2:22]
				usr_email = self.usr_email
				assert usr_email is not None
				if settings.DEBUG and settings.DEBUG_MSNP: print(F"Token: {token}")
				tpl = (backend.auth_service.get_token('nb/login', token) if dialect >= 18 else backend.auth_service.pop_token('nb/login', token))
				option = None
				if tpl is not None:
					uuid = tpl[0]
					if uuid is not None:
						response = None
						if dialect >= 15:
							rps = False
							if dialect >= 16:
								if len(args) == 3:
									rps = True
							else:
								if len(args) > 1:
									rps = True
							
							if settings.DEBUG and settings.DEBUG_MSNP: print('RPS authentication:', rps)
							
							if rps:
								assert self.rps_challenge is not None
								
								response_b64 = args[1]
								try:
									response = base64.b64decode(response_b64)
								except:
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
								
								if len(response) < 28:
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
								
								if struct.unpack('<I', response[0:4])[0] != 28 or struct.unpack('<I', response[4:8])[0] != 1 or struct.unpack('<I', response[8:12])[0] != 0x6603 or struct.unpack('<I', response[12:16])[0] != 0x8004 or struct.unpack('<I', response[16:20])[0] != 8 or struct.unpack('<I', response[20:24])[0] != 20 or struct.unpack('<I', response[24:28])[0] != 72:
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
								
								response_payload = response[28:]
								
								if not len(response_payload) == (8+20+72):
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
								
								response_iv = response_payload[0:8]
								response_hash = response_payload[8:28]
								response_cipher = response_payload[28:100]
								
								binarysecret_b64 = tpl[1]
								
								if binarysecret_b64 is None:
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
								
								binarysecret = base64.b64decode(binarysecret_b64)
								
								key2 = generate_rps_key(binarysecret, b'WS-SecureConversationSESSION KEY HASH')
								key3 = generate_rps_key(binarysecret, b'WS-SecureConversationSESSION KEY ENCRYPTION')
								
								response_hash_server = hmac.new(key2, self.rps_challenge, sha1).digest()
								
								response_cipher_server = encrypt_with_key_and_iv_tripledes_cbc(key3, response_iv, (self.rps_challenge + b'\x08\x08\x08\x08\x08\x08\x08\x08'))
								
								if response_hash != response_hash_server or response_cipher != response_cipher_server:
									self.send_reply(Err.AuthFail, trid)
									self.close(hard = True)
									return
						if dialect >= 16:
							# Only check the # of args since people could connect from either patched `msidcrl40.dll` or vanilla `msidcrl40.dll`
							if 2 <= len(args) <= 3:
								machineguid = (args[2] if len(args) >= 3 else args[1])
						
							if machineguid is not None and not re.match(r'^\{?[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}\}?', machineguid):
								self.send_reply(Err.AuthFail, trid)
								self.close(hard = True)
								return
							if machineguid is not None:
								user = backend._load_user_record(uuid)
								if user is None:
									return
								bses_self = backend.util_get_sessions_by_user(user)
								for bs_self in bses_self:
									pop_id = bs_self.front_data.get('msn_pop_id')
									if pop_id is not None and pop_id.lower() == machineguid.lower().replace('{', '').replace('}', ''):
										option = LoginOption.BootOthers
										break
									if pop_id is None:
										option = LoginOption.BootOthers
										break
								if not option:
									option = LoginOption.NotifyOthers
							else:
								option = LoginOption.BootOthers
						else:
							option = LoginOption.BootOthers
						bs = backend.login(uuid, self.client, BackendEventHandler(self), option = option)
						assert bs is not None
						self.bs = bs
						bs.front_data['msn'] = True
						if dialect >= 16 and machineguid is not None:
							bs.front_data['msn_pop_id'] = machineguid.lower().replace('{', '').replace('}', '')
						self._util_usr_final(trid, token, machineguid)
						return
		
		self.send_reply(Err.AuthFail, trid)
		self.close(hard = True)
	
	def _util_usr_final(self, trid: str, token: str, machineguid: Optional[str]) -> None:
		bs = self.bs
		
		if bs is None:
			self.send_reply(Err.AuthFail, trid)
			self.close(hard = True)
			return
		
		self.backend.util_set_sess_token(bs, token)
		
		dialect = self.dialect
		
		user = bs.user
		
		if dialect < 10:
			args = (user.status.name,) # type: Tuple[Any, ...]
		else:
			args = ()
		if dialect >= 8:
			#verified = user.verified
			verified = True
			args += ((1 if verified else 0), 0)
		
		self.send_reply('USR', trid, 'OK', user.email, *args)
		
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
			if 16 <= dialect < 21:
				# MSNP21 doesn't use this; unsure if 19/20 use it
				if dialect >= 18:
					rst = ('1:' + user.email,) # type: Tuple[str, ...]
				else:
					rst = (user.email, '1')
				self.send_reply('UBX', *rst, b'')
		
		msg1 = encode_payload(PAYLOAD_MSG_1,
			time = int(now.timestamp()),
		)
		
		if dialect >= 3:
			(high, low) = _uuid_to_high_low(user.uuid)
			
			msg1 += encode_payload(PAYLOAD_MSG_1_1,
				high = high, low = low,
				token = token,
			)
			
			if dialect >= 8:
				(ip, port) = self.peername
				
				msg1 += encode_payload(PAYLOAD_MSG_1_2,
					ip = ip, port = port,
				)
				
				if dialect >= 13:
					msg1 += encode_payload(PAYLOAD_MSG_1_3)
					
					if dialect >= 16:
						msg1 += encode_payload(PAYLOAD_MSG_1_4,
							mpop = (0 if not machineguid else 1),
						)
		
		msg1 += '\r\n'.encode('utf-8')
		
		self.send_reply('MSG', 'Hotmail', 'Hotmail', msg1)
		
		if dialect >= 13:
			msg2 = encode_payload(PAYLOAD_MSG_2,
				ct = 'text/x-msmsgsinitialmdatanotification', md = gen_mail_data(user, self.backend),
			)
			self.send_reply('MSG', 'Hotmail', 'Hotmail', msg2)
	
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
		
		if dialect < 10:
			self.syn_ser = int(extra[0])
			ser = self._ser()
			if dialect < 7:
				self.send_reply('SYN', trid, ser)
				for lst in (Lst.FL, Lst.AL, Lst.BL, Lst.RL):
					cs = [c for c in contacts.values() if c.lists & lst]
					if cs:
						for i, c in enumerate(cs):
							self.send_reply('LST', trid, lst.name, ser, len(cs), i + 1, c.head.email, c.status.name or c.head.email)
					else:
						self.send_reply('LST', trid, lst.name, ser, 0, 0)
				self.send_reply('GTC', trid, ser, settings.get('GTC', 'A'))
				self.send_reply('BLP', trid, ser, settings.get('BLP', 'AL'))
			elif dialect == 7:
				self.send_reply('SYN', trid, ser)
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
									self.send_reply('BPR', bpr_setting, bpr_value)
					else:
						self.send_reply('LST', trid, lst.name, ser, 0, 0)
				self.send_reply('GTC', trid, ser, settings.get('GTC', 'A'))
				self.send_reply('BLP', trid, ser, settings.get('BLP', 'AL'))
			else:
				num_groups = len(detail._groups_by_id.values()) + 1
				self.send_reply('SYN', trid, ser, len(contacts), num_groups)
				self.send_reply('GTC', settings.get('GTC', 'A'))
				self.send_reply('BLP', settings.get('BLP', 'AL'))
				for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
					prp_value = settings.get(prp_setting)
					if prp_value:
						self.send_reply('PRP', prp_setting, prp_value)
				self.send_reply('PRP', 'MFN', user.status.name)
				self.send_reply('LSG', '0', "Other Contacts", 0)
				for g in detail._groups_by_id.values():
					self.send_reply('LSG', g.id, g.name, 0)
				for c in contacts.values():
					self.send_reply('LST', c.head.email, c.status.name or c.head.email, int(c.lists), ','.join([group.id for group in c._groups.copy()]) or '0')
					for bpr_setting in ('PHH','PHM','PHW','MOB'):
						bpr_value = c.head.settings.get(bpr_setting)
						if bpr_value:
							self.send_reply('BPR', bpr_setting, bpr_value)
			self.syn_sent = True
		elif 10 <= self.dialect <= 12:
			self.send_reply('SYN', trid, TIMESTAMP, TIMESTAMP, len(contacts), len(detail._groups_by_id.values()))
			self.send_reply('GTC', settings.get('GTC', 'A'))
			self.send_reply('BLP', settings.get('BLP', 'AL'))
			for prp_setting in ('PHH','PHW','PHM','MOB','MBE'):
				prp_value = settings.get(prp_setting)
				if prp_value:
					self.send_reply('PRP', prp_setting, prp_value)
			self.send_reply('PRP', 'MFN', user.status.name)
			
			for g in detail._groups_by_id.values():
				self.send_reply('LSG', g.name, (g.id if self.dialect == 10 else g.uuid))
			for c in contacts.values():
				#if self.backend.util_msn_is_circle_user(c.head.uuid):
				self.send_reply('LST', 'N={}'.format(c.head.email), 'F={}'.format(c.status.name or c.head.email), 'C={}'.format(c.head.uuid),
					int(c.lists), (None if dialect < 12 else '1'), ','.join([(group.id if self.dialect == 10 else group.uuid) for group in c._groups.copy()])
				)
				for bpr_setting in ('PHH','PHM','PHW','MOB'):
					bpr_value = c.head.settings.get(bpr_setting)
					if bpr_value:
						self.send_reply('BPR', bpr_setting, bpr_value)
			self.syn_sent = True
		else:
			self.send_reply(Err.CommandDisabled, trid)
			return
	
	def _m_gcf(self, trid: str, filename: str) -> None:
		if self.dialect < 11:
			self.close(hard = True)
			return
		if self.dialect < 13 and not self.syn_sent:
			self.send_reply(Err.NotExpected, trid)
			return
		self.send_reply('GCF', trid, filename, SHIELDS)
	
	def _m_png(self) -> None:
		self.send_reply('QNG', (60 if self.dialect >= 9 else None))
	
	def _m_uux(self, trid: str, data: bytes) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		dialect = self.dialect
		
		elm = parse_xml(data.decode('utf-8'))
		
		ed = elm.find('EndpointData')
		if ed:
			capabilities = ed.find('Capabilities').text
			capabilities_lst = decode_capabilities_capabilitiesex(capabilities)
			if capabilities_lst:
				bs.front_data['msn_capabilities'] = capabilities_lst[0] or 0
				bs.front_data['msn_capabilitiesex'] = capabilities_lst[1] or 0
		
		ped = elm.find('PrivateEndpointData')
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
				self.close(hard = True)
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
			'needs_notify': (True if ddp is not None or sigsound is not None or scene is not None or colorscheme is not None else False),
			'notify_self': (True if self.dialect >= 16 and user.status.substatus is not Substatus.Offline else False),
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
		self.send_reply('ADG', trid, self._ser(), name, (group.id if self.dialect < 11 else group.uuid), 0)
	
	def _m_rmg(self, trid: str, group_id: str) -> None:
		#>>> RMG 250 00000000-0000-0000-0001-000000000001
		bs = self.bs
		assert bs is not None
		
		if group_id == 'New%20Group':
			# Bug: MSN 7.0 sends name instead of id in a particular scenario
			detail = bs.user.detail
			assert detail is not None
			
			for g in detail._groups_by_id.values():
				if g.name != 'New Group': continue
				group_id = (g.id if self.dialect < 11 else g.uuid)
				break
		
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
			d_els = adl_xml.findall('d')
			for d_el in d_els:
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close(hard = True)
					return
			for d_el in d_els:
				domain = d_el.get('n')
				c_els = d_el.findall('c')
				try:
					c_nids = [NetworkID(int(c_el.get('t'))) for c_el in c_els]
					if NetworkID.CIRCLE in c_nids:
						if NetworkID.WINDOWS_LIVE in c_nids or NetworkID.OFFICE_COMMUNICATOR in c_nids or NetworkID.TELEPHONE in c_nids or NetworkID.MNI in c_nids or NetworkID.SMTP in c_nids or NetworkID.YAHOO in c_nids:
							self.send_reply(Err.XXLInvalidPayload, trid)
							self.close(hard = True)
							return
						circle_mode = True
				except ValueError:
					self.send_reply(Err.InvalidNetworkID, trid)
					self.close(hard = True)
					return
				
				if circle_mode:
					if domain != 'live.com':
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close(hard = True)
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
					#				self.close(hard = True)
					#				return
					#	if lsts is None: continue
					
					try:
						lsts = Lst(int(c_el.get('l')))
					except ValueError:
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close(hard = True)
						return
					
					if lsts & (Lst.RL | Lst.PL):
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close(hard = True)
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
						if backend.user_service.get_groupchat(chat_id or '') is None:
							self.send_reply(Err.InvalidCircleMembership, trid)
							return
			
			if not circle_mode and not self.initial_adl_sent:
				self.initial_adl_sent = True
			
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
						chat_id = username[-12:]
						if lsts & Lst.FL:
							groupchat = backend.user_service.get_groupchat(chat_id)
							if groupchat is None: continue
							
							for membership in groupchat.memberships.values():
								for bs in backend.util_get_sessions_by_user(membership.head):
									bs.evt.on_groupchat_presence_notification(groupchat, membership.head)
					else:
						email = '{}@{}'.format(username, domain)
						contact_uuid = backend.util_get_uuid_from_email(email)
						
						if contact_uuid is not None:
							old_ctc = detail.contacts.get(contact_uuid)
							
							try:
								ctc, _ = bs.me_contact_add(contact_uuid, lsts, name = email)
							except Exception:
								pass
							
							if lsts & Lst.FL:
								if ctc is not None and old_ctc is None:
									bs.evt.on_presence_notification(None, ctc, False, trid = trid)
		except Exception as ex:
			if isinstance(ex, XMLSyntaxError):
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close(hard = True)
			else:
				self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
				return
		
		self.send_reply('ADL', trid, 'OK')
	
	def _m_rml(self, trid: str, data: bytes) -> None:
		backend = self.backend
		bs = self.bs
		assert bs is not None
		d_el = None
		
		try:
			rml_xml = parse_xml(data.decode('utf-8'))
			d_els = rml_xml.findall('d')
			for d_el in d_els:
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close(hard = True)
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
					#				self.close(hard = True)
					#				return
					#	if lsts is None: continue
					
					try:
						networkid = NetworkID(int(c_el.get('t')))
						
						#if networkid in (NetworkID.OFFICE_COMMUNICATOR,NetworkID.TELEPHONE,NetworkID.MNI,NetworkID.SMTP):
						#	self.send_reply(Err.InvalidUser2, trid)
						#	return
					except ValueError:
						self.send_reply(Err.InvalidNetworkID, trid)
						self.close(hard = True)
						return
					try:
						lsts = Lst(int(c_el.get('l')))
					except ValueError:
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close(hard = True)
						return
					
					if lsts & (Lst.RL | Lst.PL):
						self.send_reply(Err.XXLInvalidPayload, trid)
						self.close(hard = True)
						return
					
					username = c_el.get('n')
					email = '{}@{}'.format(username, domain)
				
				for c_el in c_els:
					lsts = None
					
					username = c_el.get('n')
					email = '{}@{}'.format(username, domain)
					
					#if self.dialect == 21:
					#	s_els = c_el.findall('s')
					#	for s_el in s_els:
					#		if s_el is not None and s_el.get('n') == 'IM':
					#			lsts = Lst(int(s_el.get('l')))
					#	if lsts is None: continue
					
					lsts = Lst(int(c_el.get('l')))
					
					contact_uuid = self.backend.util_get_uuid_from_email(email)
					
					if contact_uuid is not None:
						try:
							bs.me_contact_remove(contact_uuid, lsts)
						except Exception:
							pass
		except Exception as ex:
			if isinstance(ex, XMLSyntaxError):
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close(hard = True)
				return
			else:
				self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
				return
		
		self.send_reply('RML', trid, 'OK')
	
	def _m_adc(self, trid: str, lst_name: str, arg1: str, arg2: Optional[str] = None) -> None:
		if self.dialect < 10:
			self.close(hard = True)
			return
		if arg1.startswith('N='):
			#>>> ADC 249 BL N=bob1@hotmail.com
			#>>> ADC 278 AL N=foo@hotmail.com
			#>>> ADC 277 FL N=foo@hotmail.com F=foo@hotmail.com
			email = arg1[2:]
			if not re.match(r'^[a-zA-Z0-9._\-]+@([a-zA-Z0-9\-]+\.)+[a-zA-Z]+$', email):
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
			self.close(hard = True)
			return
		if not re.match(r'^[a-zA-Z0-9._\-]+@([a-zA-Z0-9\-]+\.)+[a-zA-Z]+$', email):
			self.send_reply(Err.InvalidParameter, trid)
			return
		contact_uuid = self.backend.util_get_uuid_from_email(email)
		self._add_common(trid, lst_name, contact_uuid, name, group_id)
	
	def _add_common(self, trid: str, lst_name: str, contact_uuid: Optional[str], name: Optional[str] = None, group_id: Optional[str] = None) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		send_bpr_info = False
		
		if contact_uuid is None:
			if self.dialect >= 10:
				self.send_reply(Err.InvalidUser2, trid)
			else:
				self.send_reply(Err.InvalidUser, trid)
			return
		
		lst = getattr(Lst, lst_name)
		
		try:
			ctc, ctc_head = bs.me_contact_add(contact_uuid, lst, name = name, group_id = group_id)
		except Exception as ex:
			self.send_reply(Err.GetCodeForException(ex, self.dialect), trid)
			return
		
		ser = self._ser()
		
		if self.dialect >= 10:
			if lst == Lst.FL:
				if group_id:
					self.send_reply('ADC', trid, lst_name, 'C={}'.format(ctc_head.uuid), group_id)
				else:
					self.send_reply('ADC', trid, lst_name, 'N={}'.format(ctc_head.email), ('F={}'.format(ctc.status.name) if ctc.status.name else None), 'C={}'.format(ctc_head.uuid))
			else:
				self.send_reply('ADC', trid, lst_name, 'N={}'.format(ctc.status.name or ctc_head.email))
		else:
			self.send_reply('ADD', trid, lst_name, ser, ctc_head.email, name, group_id)
		
		if lst == Lst.FL and not group_id:
			if self.syn_sent:
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
			
			bs.evt.on_presence_notification(None, ctc, False, trid = trid, updated_phone_info = {
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
			bs.close(hard = True)
			return
		if lst is Lst.FL:
			#>>> REM 279 FL 00000000-0000-0000-0002-000000000001
			#>>> REM 247 FL 00000000-0000-0000-0002-000000000002 00000000-0000-0000-0001-000000000002
			if self.dialect < 10:
				contact_uuid = self.backend.util_get_uuid_from_email(usr)
			else:
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
			self.close(hard = True)
		# "Alert me when other people add me ..." Y/N
		#>>> GTC 152 N
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if value not in ('A','N'):
			self.close(hard = True)
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
			self.close(hard = True)
			return
		if user.settings.get('BLP') == value and self.dialect < 13:
			self.send_reply(Err.AlreadyInMode, trid)
			return
		bs.me_update({ 'blp': value })
		self.send_reply('BLP', trid, self._ser(), value)
	
	def _m_chg(self, trid: str, sts_name: str, capabilities: Optional[str] = None, msnobj: Optional[str] = None) -> None:
		#>>> CHG 120 BSY 1073791020 <msnobj .../>
		dialect = self.dialect
		bs = self.bs
		assert bs is not None
		
		capabilities_msn = None # type: Optional[str]
		capabilities_msn_ex = None # type: Optional[str]
		
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
			'substatus': MSNStatus.ToSubstatus(getattr(MSNStatus, sts_name)),
			'refresh_profile': True,
		})
		
		extra = () # type: Tuple[Any, ...]
		if dialect >= 9:
			extra = (encode_msnobj(msnobj),)
		
		self.send_reply('CHG', trid, sts_name, capabilities, *extra)
		
		# Send ILNs (and system messages, if any)
		if not self.iln_sent:
			self.iln_sent = True
			user = bs.user
			detail = user.detail
			assert detail is not None
			dialect = self.dialect
			for ctc in detail.contacts.values():
				for m in build_presence_notif(trid, ctc.head, user, dialect, self.backend, self.iln_sent):
					self.send_reply(*m)
			# TODO: There's a weird timeout issue with the challenges on 8.x. Comment out for now
			#if dialect >= 6:
			#	self._send_chl(trid)
			if self.backend.notify_maintenance:
				bs.evt.on_system_message(1, self.backend.maintenance_mins)
		
		if dialect >= 16:
			bs.me_update({
				'notify_self': True,
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
		#	self.close(hard = True)
		#	return
		#
		#id_key, max_dialect = _QRY_ID_CODES[client_id]
		#
		#if self.dialect > max_dialect:
		#	self.send_reply(Err.ChallengeResponseFailed, trid)
		#	self.close(hard = True)
		#	return
		#
		#server_response = gen_chal_response(challenge, client_id, id_key, msnp11 = (self.dialect >= 11))
		#
		#if response.decode() != server_response:
		#	self.send_reply(Err.ChallengeResponseFailed, trid)
		#	self.close(hard = True)
		#	return
		#
		#self.send_reply('QRY', trid)
		
		return
	
	def _m_put(self, trid: str, data: bytes) -> None:
		# `PUT` only used for circles in MSNP18
		
		backend = self.backend
		bs = self.bs
		assert bs is not None
		user = bs.user
		detail = user.detail
		assert detail is not None
		
		pop_id_other = None
		circle_mode = False
		chat_id = None
		#presence = False
		
		i = data.index(b'\r\n\r\n') + 4
		headers = Parser().parsestr(data[:i].decode('utf-8'))
		
		to = _split_email_put(str(headers['To']))
		from_email = _split_email_put(str(headers['From']))
		
		if to[1] is NetworkID.CIRCLE:
			circle_mode = True
			print(to[0])
			if not to[0].endswith('@live.com'): return
			email_end = to[0].rfind('@live.com')
			circle_id = to[0][:email_end]
			if not (circle_id.startswith('00000000-0000-0000-0009-') and len(circle_id[24:]) == 12):
				return
			chat_id = circle_id[-12:]
		else:
			ctc_uuid = backend.util_get_uuid_from_email(to[0])
		
		#if to[0] != user.email:
		#	ctc_uuid = backend.util_get_uuid_from_email(to[0])
		#	if ctc_uuid is None:
		#		return
		#	ctc = detail.contacts.get(ctc_uuid)
		#	if ctc is None:
		#		return
		
		body = data[i:].decode()
		nfy_1_index = body.find('\r\n\r\n')
		nfy_actual = body[nfy_1_index+4:]
		
		print(nfy_actual)
		
		payload_index = nfy_actual.find('\r\n\r\n')
		nfy_headers = Parser().parsestr(nfy_actual[:payload_index])
		payload = nfy_actual[payload_index+4:]
		
		if nfy_headers.get('Content-Type') == 'application/circles+xml':
			if chat_id is None: return
			
			groupchat = backend.user_service.get_groupchat(chat_id)
			if groupchat is None: return
			
			elm = parse_xml(payload)
			email_elm = elm.find('roster/user/id')
			if email_elm is not None:
				email = email_elm.text
				if not email.startswith('1:'): return
				email = email.split('1:', 1)[1]
				if email == user.email:
					try:
						backend.join_groupchat(chat_id, bs, GroupChatEventHandler(self, bs), pop_id = bs.front_data.get('msn_pop_id'))
					except:
						pass
			
			presence_elm = elm.find('props/presence')
			if presence_elm is not None:
				cs = backend.get_groupchat_cs(chat_id, bs)
				if cs is None: return
				
				mfn_elm = presence_elm.find('Data/MFN')
				if mfn_elm is not None:
					cs.front_data['msn_circle_mfn'] = mfn_elm.text
				psm_elm = presence_elm.find('Data/PSM')
				if psm_elm is not None:
					cs.front_data['msn_circle_psm'] = psm_elm.text
				cm_elm = presence_elm.find('Data/CurrentMedia')
				if cm_elm is not None:
					cs.front_data['msn_circle_cm'] = cm_elm.text
				
				cs.update_status()
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
		#						self.close(hard = True)
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
		#						self.close(hard = True)
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
		#						self.close(hard = True)
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
		#						self.close(hard = True)
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
		#				for m in build_presence_notif(trid, ctc.head, user, self.dialect, self.backend, self.iln_sent):
		#					self.send_reply(*m)
		#		
		#		self.send_reply('PUT', trid, 'OK', b'')
		#		return
		#	except XMLSyntaxError:
		#		self.close(hard = True)
		#		return
		#
		#if ctc is not None:
		#	for ctc_sess in backend.util_get_sessions_by_user(ctc.head):
		#		pop_id_other = ctc_sess.front_data.get('msn_pop_id')
		#		if pop_id_other:
		#			if to[2] is not None:
		#				if pop_id_other.lower() != to[2].lower().replace('{', '').replace('}', ''):
		#					continue
		#				else:
		#					pop_id_other = to[2].replace('{', '').replace('}', '')
		#		ctc_sess.evt.msn_on_put_sent(data, user, pop_id_sender = from_email[2], pop_id = pop_id_other)
		#
		self.send_reply('PUT', trid, 'OK', b'')
		
		return
	
	def _m_rea(self, trid: str, email: str, name: str) -> None:
		if self.dialect >= 10:
			self.send_reply(Err.CommandDisabled, trid)
			return
		
		bs = self.bs
		assert bs is not None
		
		if email == bs.user.email:
			bs.me_update({ 'name': name })
		self.send_reply('REA', trid, self._ser(), email, name)
	
	def _m_snd(self, trid: str, email: str) -> None:
		# Send email about how to use MSN. Ignore it for now.
		self.send_reply('SND', trid, email)
	
	def _m_prp(self, trid: str, key: str, value: Optional[str] = None, *rest: Optional[str]) -> None:
		#>>> PRP 115 MFN ~~woot~~
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		if key == 'MFN':
			bs.me_update({ 'name': value })
		elif key.startswith('PH'):
			if len(key) > 3:
				self.close(hard = True)
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
				self.close(hard = True)
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
		token = self.backend.auth_service.create_token('sb/xfr', (bs, dialect), lifetime = 120)
		extra = () # type: Tuple[Any, ...]
		if dialect >= 13:
			extra = ('U', 'messenger.msn.com')
		if dialect >= 14:
			extra += (1,)
		self.send_reply('XFR', trid, dest, 'm1.escargot.log1p.xyz:1864', 'CKI', token, *extra)
	
	def _m_fqy(self, trid: str, data: bytes) -> None:
		# "Federated query; Query contact's network types"
		# https://web.archive.org/web/20100820020114/http://msnpiki.msnfanatic.com:80/index.php/Command:FQY
		# 
		# Just return what the client sends us until we can implement the protocol Yahoo! Messenger 8.0 uses (the version of Yahoo! that
		# supports the Yahoo/MSN interop)
		d_els = None
		domain = None
		username = None
		networkid = None
		contact_uuid = None
		
		try:
			fqy_xml = parse_xml(data.decode('utf-8'))
			d_els = fqy_xml.findall('d')
			if len(d_els) == 1:
				d_el = d_els[0]
				if len(d_el.getchildren()) == 0:
					self.send_reply(Err.XXLEmptyDomain, trid)
					self.close(hard = True)
				elif len(d_el.getchildren()) > 1:
					self.send_reply(Err.XXLInvalidPayload, trid)
					self.close(hard = True)
			else:
				self.send_reply(Err.XXLInvalidPayload, trid)
				self.close(hard = True)
			
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
				self.close(hard = True)
		
		self.send_reply('FQY', trid, '<ml><d n="{}"><c n="{}" t="1" /></d></ml>'.format(
			domain, username,
		).encode('utf-8'))
	
	def _m_uun(self, trid: str, email: str, type: str, data: Optional[bytes] = None) -> None:
		# "Send sharing invitation or reply to invitation"
		# https://web.archive.org/web/20130926060507/http://msnpiki.msnfanatic.com/index.php/MSNP13:Changes#UUN
		bs = self.bs
		assert bs is not None
		
		pop_id_self = None
		
		(email, pop_id) = decode_email_pop(email)
		
		contact_uuid = self.backend.util_get_uuid_from_email(email)
		if contact_uuid is None:
			return
		try:
			uun_type = int(type)
		except ValueError:
			return
		
		if uun_type is not None:
			if uun_type == 1 and data:
				try:
					snm = parse_xml(data.decode('utf-8'))
					opcode = snm.get('opcode')
					
					if opcode in ('SNM','ACK'):
						self.send_reply('UUN', trid, 'OK')
				except:
					return
			elif uun_type in (3, 11):
				# Initiating a voice call on WLM sends a `UUN` command with some integers instead of an `<SNM>` XML ('UUN <trid> <passport> 11\r\n\r\n1 1 0 134546710 144000000')
				# Send a response in that case.
				self.send_reply('UUN', trid, 'OK')
		else:
			return
		
		pop_id_self = bs.front_data.get('msn_pop_id')
		
		bs.me_send_uun_invitation(contact_uuid, uun_type, data, pop_id_sender = pop_id_self, pop_id = pop_id)
	
	def _m_uum(self, trid: str, email: str, networkid: str, type: str, data: bytes) -> None:
		# For federated messaging (with Yahoo!); also used in MSNP18+ for OIMs
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		
		nid = None # type: Optional[NetworkID]
		
		message = None
		
		if type not in ('1','2','3','4'):
			self.close(hard = True)
			return
		
		try:
			nid = NetworkID(int(networkid))
		except ValueError:
			self.close(hard = True)
			return
		
		assert nid is not None
		
		if nid is NetworkID.WINDOWS_LIVE and self.dialect < 18:
			self.close(hard = True)
			return
		
		if nid is not NetworkID.WINDOWS_LIVE:
			return
		
		if type != '1':
			self.close(hard = True)
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
			
			self.backend.user_service.save_oim(bs, ctc_head.uuid, gen_uuid(), ip, message, True, from_friendly = user.status.name, oim_proxy = 'MSNMSGR')
		except:
			return
	
	def _send_chl(self, trid: str) -> None:
		backend = self.backend
		
		self.challenge = str(secrets.randbelow(89999999999999999999) + 10000000000000000000)
		backend.loop.create_task(self._check_qry_sent(trid))
		self.send_reply('CHL', 0, self.challenge)
	
	async def _check_qry_sent(self, trid: str) -> None:
		await asyncio.sleep(50)
		
		if self.challenge:
			self.send_reply(Err.ChallengeResponseFailed, trid)
			self.close(hard = True)
	
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
	
	def on_presence_notification(self, bs_other: Optional[BackendSession], ctc: Contact, on_contact_add: bool, *, trid: Optional[str] = None, update_status: bool = True, send_status_on_bl: bool = False, visible_notif: bool = True, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		if not update_status or (send_status_on_bl and not update_status): return
		if self.ctrl.dialect < 13 and updated_phone_info and self.ctrl.syn_sent:
			for phone_type, value in updated_phone_info.items():
				if value is not None:
					self.ctrl.send_reply('BPR', self.ctrl._ser(), ctc.head.email, phone_type, value)
		if update_status:
			for m in build_presence_notif(trid, ctc.head, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, bs_other = bs_other):
				self.ctrl.send_reply(*m)
			return
	
	def on_groupchat_presence_notification(self, groupchat: GroupChat, user_other: User) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		for m in build_presence_notif(None, user_other, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, groupchat = groupchat):
			self.ctrl.send_reply(*m)
		return
	
	def on_presence_self_notification(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		for m in build_presence_notif(None, user, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, self_presence = True):
			self.ctrl.send_reply(*m)
		return
	
	def on_chat_invite(self, chat: Chat, inviter: User, *, inviter_id: Optional[str] = None, invite_msg: str = '') -> None:
		extra = () # type: Tuple[Any, ...]
		dialect = self.ctrl.dialect
		if dialect >= 13:
			extra = ('U', 'messenger.hotmail.com')
		if dialect >= 14:
			extra += (1,)
		token = self.ctrl.backend.auth_service.create_token('sb/cal', (self.ctrl.bs, dialect, chat), lifetime = 120)
		self.ctrl.send_reply('RNG', chat.ids['main'], 'm1.escargot.log1p.xyz:1864', 'CKI', token, inviter.email, inviter.status.name, *extra)
	
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
				m: Tuple[Any, ...] = ('ADD', 0, self.ctrl._ser(), Lst.RL.name, email, name)
			else:
				m = ('ADC', 0, Lst.RL.name, 'N={}'.format(email), 'F={}'.format(name))
		else:
			username, domain = email.split('@', 1)
			adl_payload = '<ml l="1"><d n="{}"><c n="{}" l="{}" t="1"/></d></ml>'.format(
				domain, username, int(Lst.RL),
			)
			m = ('ADL', 0, adl_payload.encode('utf-8'))
		self.ctrl.send_reply(*m)
	
	def on_contact_request_denied(self, user_added: User, message: Optional[str], *, contact_id: Optional[str] = None) -> None:
		pass
	
	def on_oim_sent(self, oim: 'OIM') -> None:
		assert self.ctrl.bs is not None
		self.ctrl.send_reply('MSG', 'Hotmail', 'Hotmail', encode_payload(PAYLOAD_MSG_2,
			ct = 'text/x-msmsgsoimnotification', md = gen_mail_data(self.ctrl.bs.user, self.ctrl.backend, oim = oim, just_sent = True, e_node = False, q_node = False)
		))
	
	def msn_on_oim_deletion(self, oims_deleted: int) -> None:
		self.ctrl.send_reply('MSG', 'Hotmail', 'Hotmail', encode_payload(PAYLOAD_MSG_3, oims_deleted = str(oims_deleted)))
	
	def msn_on_uun_sent(self, sender: User, type: int, data: Optional[bytes], *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
		ctrl = self.ctrl
		bs = ctrl.bs
		assert bs is not None
		
		if ctrl.dialect < 13:
			return
		
		if pop_id is not None and 'msn_pop_id' in bs.front_data:
			pop_id_self = bs.front_data.get('msn_pop_id') or ''
			if pop_id.lower().replace('{', '').replace('}', '') != pop_id_self.lower(): return
		
		if pop_id_sender is not None and pop_id is not None and ctrl.dialect >= 16:
			email = '{};{}'.format(sender.email, '{' + pop_id_sender + '}')
		else:
			email = sender.email
		
		self.ctrl.send_reply('UBN', email, type, data)
	
	def msn_on_notify_ab(self) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		id_bits = _uuid_to_high_low(user.uuid)
		self.ctrl.send_reply('NOT', encode_payload(PAYLOAD_MSG_4,
			member_low = binascii.hexlify(struct.pack('!I', id_bits[1])).decode('utf-8'), member_high = binascii.hexlify(struct.pack('!I', id_bits[0])).decode('utf-8'), email = user.email,
			cid = cid_format(user.uuid, decimal = True), now = date_format(datetime.utcnow()),
		))
	
	def msn_on_circle_role(self, chat_id: str, *, role: Optional[GroupChatRole] = None) -> None:
		bs = self.ctrl.bs
		assert bs is not None
		user = bs.user
		
		id_bits = _uuid_to_high_low(user.uuid)
		if role is None:
			role = GroupChatRole.Member
		
		self.ctrl.send_reply('NOT', encode_payload(PAYLOAD_MSG_7,
			member_low = binascii.hexlify(struct.pack('!I', id_bits[1])).decode('utf-8'), member_high = binascii.hexlify(struct.pack('!I', id_bits[0])).decode('utf-8'), email = user.email,
			chat_id = chat_id, role = role.name,
		))
	
	def msn_on_put_sent(self, payload: bytes, sender: User, *, pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None) -> None:
		#ctrl = self.ctrl
		#bs = ctrl.bs
		#assert bs is not None
		#data = b''
		#
		#if ctrl.dialect < 18:
		#	return
		#
		#message = Parser().parsestr(payload.decode('utf-8'))
		#del message['To']
		#del message['From']
		#message['To'] = _encode_networkid_email_pop('1:{}'.format(bs.user.email), pop_id)
		#message['From'] = _encode_networkid_email_pop('1:{}'.format(bs.user.email), pop_id_sender)
		#
		#for variable, content in message.items():
		#	data += '{}: {}\r\n'.format(
		#		variable, content,
		#	).encode('utf-8')
		#data += b'\r\n'
		#
		#put_payload = message.get_payload()
		#if isinstance(put_payload, str):
		#	data += put_payload.encode('utf-8')
		#elif isinstance(put_payload, bytes):
		#	data += put_payload
		#
		#self.ctrl.send_reply('NFY', 'PUT', data)
		
		return
	
	def ymsg_on_xfer_init(self, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		pass
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		# TODO: Pass file transfer message to any chats with Yahoo! user
		pass
	
	def on_login_elsewhere(self, option: LoginOption) -> None:
		if option is LoginOption.BootOthers:
			self.ctrl.send_reply('OUT', 'OTH')
		elif option is LoginOption.NotifyOthers:
			if not self.ctrl.dialect >= 16:
				self.ctrl.send_reply('OUT', 'OTH')
		else:
			# TODO: What do?
			pass
	
	def on_close(self, *, maintenance: bool = False) -> None:
		bs = self.bs
		assert bs is not None
		backend = bs.backend
		
		#if bs.front_data.get('msn_circle_sessions') is not None:
		#	for circle_bs in bs.front_data.get('msn_circle_sessions').copy():
		#		circle_bs.close()
		
		self.ctrl.close(maintenance = maintenance)

class GroupChatEventHandler(event.ChatEventHandler):
	__slots__ = ('ctrl', 'bs', 'cs')
	
	ctrl: MSNPCtrlNS
	bs: BackendSession
	cs: ChatSession
	
	def __init__(self, ctrl: MSNPCtrlNS, bs: BackendSession) -> None:
		self.ctrl = ctrl
		self.bs = bs
	
	def on_participant_joined(self, cs_other: ChatSession, first_pop: bool) -> None:
		if not first_pop: return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		cs = self.cs
		groupchat = cs.chat.groupchat
		assert groupchat is not None
		
		result = CIRCLE_ROSTER.format(users = CIRCLE_USER.format(email = cs_other.user.email))
		
		self.ctrl.send_reply('NFY', 'PUT', encode_payload(PAYLOAD_MSG_5,
			email = user.email, chat_id = groupchat.chat_id,
			cl = len(result), payload = result,
		))
	
	def on_participant_left(self, cs_other: ChatSession, idle: bool, last_pop: bool) -> None:
		if not last_pop: return
		
		bs = self.bs
		assert bs is not None
		user = bs.user
		cs = self.cs
		groupchat = cs.chat.groupchat
		assert groupchat is not None
		
		for m in build_presence_notif(None, cs_other.user, user, self.ctrl.dialect, self.ctrl.backend, self.ctrl.iln_sent, bs_other = cs_other.bs, groupchat = groupchat):
			self.ctrl.send_reply(*m)
	
	def on_chat_user_status_updated(self, cs_other: ChatSession) -> None:
		bs = self.bs
		assert bs is not None
		user = bs.user
		cs = self.cs
		chat = cs.chat
		groupchat = chat.groupchat
		assert groupchat is not None
		
		users = ''
		
		for cs1 in chat.get_roster_single():
			users += CIRCLE_USER.format(email = cs1.user.email)
		
		roster = CIRCLE_ROSTER.format(users = users)
		
		presence = CIRCLE_PRESENCE.format(
			friendly = cs.front_data.get('msn_circle_mfn') or '', psm = cs.front_data.get('msn_circle_psm') or '', cm = cs.front_data.get('msn_circle_cm') or '',
			roster = roster,
		)
		
		self.ctrl.send_reply('NFY', 'PUT', encode_payload(PAYLOAD_MSG_6,
			email = _encode_email_epid(user.email, bs.front_data.get('msn_pop_id')), chat_id = groupchat.chat_id,
			cl = len(presence), payload = presence,
		))
	
	def on_invite_declined(self, invited_user: User, *, invited_id: Optional[str] = None, message: str = '') -> None:
		pass
	
	def on_message(self, data: MessageData) -> None:
		pass

def _split_email_put(email: str) -> Tuple[str, NetworkID, Optional[str]]:
	epid = None # type: Optional[str]
	
	email_epid = email.split(';', 1)
	networkid, email = decode_email_networkid(email_epid[0])
	if len(email_epid) > 1:
		if email_epid[1].startswith('epid='):
			epid = email_epid[1][6:-1]
	return (email, networkid, epid)

def _encode_email_epid(email: str, pop_id: Optional[str]) -> str:
	result = email
	
	if pop_id:
		result = '{};epid={}'.format(result, '{' + pop_id + '}')
	
	return result

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

# MSNP2+
PAYLOAD_MSG_1 = '''MIME-Version: 1.0
Content-Type: text/x-msmsgsprofile; charset=UTF-8
LoginTime: {time}
'''

# MSNP3+
PAYLOAD_MSG_1_1 = '''EmailEnabled: 0
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
MSPAuth: {token}Y6+H31sTUOFkqjNTDYqAAFLr5Ote7BMrMnUIzpg860jh084QMgs5djRQLLQP0TVOFkKdWDwAJdEWcfsI9YL8otN9kSfhTaPHR1njHmG0H98O2NE/Ck6zrog3UJFmYlCnHidZk1g3AzUNVXmjZoyMSyVvoHLjQSzoGRpgHg3hHdi7zrFhcYKWD8XeNYdoz9wfA2YAAAgZIgF9kFvsy2AC0Fl/ezc/fSo6YgB9TwmXyoK0wm0F9nz5EfhHQLu2xxgsvMOiXUSFSpN1cZaNzEk/KGVa3Z33Mcu0qJqvXoLyv2VjQyI0VLH6YlW5E+GMwWcQurXB9hT/DnddM5Ggzk3nX8uMSV4kV+AgF1EWpiCdLViRI6DmwwYDtUJU6W6wQXsfyTm6CNMv0eE0wFXmZvoKaL24fggkp99dX+m1vgMQJ39JblVH9cmnnkBQcKkV8lnQJ003fd6iIFzGpgPBW5Z3T1Bp7uzSGMWnHmrEw8eOpKC5ny4x8uoViXDmA2UId23xYSoJ/GQrMjqB+NslqnuVsOBE1oWpNrmfSKhGU1X0kR4Eves56t5i5n3XU+7ne0MkcUzlrMi89n2j8aouf0zeuD7o+ngqvfRCsOqjaU71XWtuD4ogu2X7/Ajtwkxg/UJDFGAnCxFTTd4dqrrEpKyMK8eWBMaartFxwwrH39HMpx1T9JgknJ1hFWELzG8b302sKy64nCseOTGaZrdH63pjGkT7vzyIxVH/b+yJwDRmy/PlLz7fmUj6zpTBNmCtl1EGFOEFdtI2R04EprIkLXbtpoIPA7m0TPZURpnWufCSsDtD91ChxR8j/FnQ/gOOyKg/EJrTcHvM1e50PMRmoRZGlltBRRwBV+ArPO64On6zygr5zud5o/aADF1laBjkuYkjvUVsXwgnaIKbTLN2+sr/WjogxT1Yins79jPa1+3dDenxZtE/rHA/6qsdJmo5BJZqNYQUFrnpkU428LryMnBaNp2BW51JRsWXPAA7yCi0wDlHzEDxpqaOnhI4Ol87ra+VAg==&p=
sid: 507
'''

# MSNP8+
PAYLOAD_MSG_1_2 = '''ClientIP: {ip}
ClientPort: {port}
'''

# MSNP10+ (for determining whether the contacts on an account had to be migrated to the address book; leave as 1 by default)
PAYLOAD_MSG_1_3 = '''ABCHMigrated: 1
'''

# MSNP16+ (possibly for determining if a logged in client either specified an MPoP GUID or could use the feature et al)
PAYLOAD_MSG_1_4 = '''MPOPEnabled: {mpop}
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

{payload}
'''

PAYLOAD_MSG_6 = '''Routing: 1.0
To: 1:{email}
From: 9:00000000-0000-0000-0009-{chat_id}@live.com

Reliability: 1.0
Stream: 1

Publication: 1.0
Uri: /circle
NotifType: Full
Content-Type: application/circles+xml
Content-Length: {cl}

{payload}
'''

PAYLOAD_MSG_7 = '''<NOTIFICATION id="0" siteid="45705" siteurl="http://contacts.msn.com">
	<TO pid="0x{member_low}:0x{member_high}" name="{email}">
		<VIA agent="messenger" />
	</TO>
	<MSG id="0">
		<SUBSCR url="s.htm" />
		<ACTION url="a.htm" />
		<BODY>
			&lt;NotificationData xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"&gt;
				&lt;CircleId&gt;00000000-0000-0000-0009-{chat_id}&lt;/CircleId&gt;
				&lt;Role&gt;{role}&lt;/Role&gt;
			&lt;/NotificationData&gt;
		</BODY>
	</MSG>
</NOTIFICATION>'''

SHIELDS = '''<?xml version="1.0" encoding="utf-8" ?>
<config>
	<shield><cli maj="7" min="0" minbld="0" maxbld="9999" deny=" " /></shield>
	<block></block>
</config>'''.encode('utf-8')
# TODO: By MSNP18 `GCF` policies have a checksum. What do?
SHIELDS_MSNP13 = '''<Policies>
	<Policy type="SHIELDS"><config> <cli maj="7" min="0" minbld="0" maxbld="9999" deny=" " /> <block> </block> </config></Policy>
	<Policy type="ABCH" checksum="03DC55910A9CB79133F1576221A80346"><policy><set id="push" service="ABCH" priority="200"> <r id="pushstorage" threshold="180000" /> </set><set id="delaysup" service="ABCH" priority="150"> <r id="whatsnew" threshold="1800000" /> <r id="whatsnew_storage_ABCH_delay" timer="1800000" /> <r id="whatsnewt_link" threshold="900000" trigger="QueryActivities" /></set> <c id="PROFILE_Rampup">100</c></policy></Policy>
	<Policy type="ERRORRESPONSETABLE" checksum="492FC3AB58364997FDDF44978227188C"><Policy> <Feature type="3" name="P2P"> <Entry hr="0x81000398" action="3"/> <Entry hr="0x82000020" action="3"/> </Feature> <Feature type="4"> <Entry hr="0x81000440" /> </Feature> <Feature type="6" name="TURN"> <Entry hr="0x8007274C" action="3" /> <Entry hr="0x82000020" action="3" /> </Feature></Policy></Policy>
	<Policy type="P2P" checksum="815D4F1FF8E39A85F1F97C4B16C45177"><ObjStr SndDly="1" /></Policy>
</Policies>'''.encode('utf-8')
CIRCLE_ROSTER = '<roster><id>IM</id>{users}</roster>'
CIRCLE_USER = '<user><id>1:{email}</id></user>'

CIRCLE_PRESENCE = '<circle><props><presence dtype="xml"><Data><UTL></UTL><MFN>{friendly}</MFN><PSM>{psm}</PSM><CurrentMedia>{cm}</CurrentMedia></Data></presence></props>{roster}</circle>'
TIMESTAMP = '2000-01-01T00:00:00.0-00:00'

_QRY_ID_CODES = {
	# MSNP6 - 9
	'msmsgs@msnmsgr.com': ('Q1P7W2E4J9R8U3S5', 10),
	'PROD0038W!61ZTF9': ('VT6PX?UQTM4WM%YR', 10),
	'PROD0058#7IL2{QD': ('QHDCY@7R1TB6W?5B', 10),
	'PROD0061VRRZH@4F': ('JXQ6J@TUOGYV@N0M', 10),
	'PROD00504RLUG%WL': ('I2EBK%PYNLZL5_J4', 10),
	'PROD0076ENE8*@AW': ('CEQJ8}OE0!WTSWII', 10),
	#'PROD00517IFH4@RV': ('<unknown>', 10),
	# MSNP11 - 12
	'PROD0090YUAUV{2B': ('YMM8C_H7KCQ2S_KL', 12),
	'PROD0101{0RM?UBW': ('CFHUR$52U_{VIX5T', 12),
	# MSNP13 - 14
	'PROD01065C%ZFN6F': ('O4BG@C7BWLYQX?5G', 14),
	'PROD0112J1LW7%NB': ('RH96F{PHI8PPX_TJ', 14),
	# MSNP15+
	'PROD0113H11T8$X_': ('RG@XY*28Q5QHS%Q5', 21),
	'PROD0114ES4Z%Q5W': ('PK}_A_0N_K%O?A9S', 21),
	'PROD0118R6%2WYOS': ('YIXPX@5I2P0UT*LK', 21),
	'PROD0119GSJUC$18': ('ILTXC!4IXB5FB*PX', 21),
	# Thanks J.M. for making the tweet with this WLM 2009 ID-key combo. ^_^
	'PROD0120PW!CCV9@': ('C1BX{V4W}Q3*10SM', 21),
}

def _uuid_to_high_low(uuid_str: str) -> Tuple[int, int]:
	import uuid
	u = uuid.UUID(uuid_str)
	high = u.time_low % (1<<32)
	low = u.node % (1<<32)
	return (high, low)
