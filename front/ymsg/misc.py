from typing import Optional, Tuple, Any, Iterable, Dict, List, ClassVar
from urllib.parse import quote_plus
from enum import IntEnum
import time, binascii, struct

from util.misc import first_in_iterable, DefaultDict, MultiDict, arbitrary_encode, arbitrary_decode

from core.backend import Backend, BackendSession, Chat, ChatSession
from core.models import User, Lst, Contact, Substatus, NetworkID

import settings

class YMSGService(IntEnum):
	LogOn = 0x01
	LogOff = 0x02
	IsAway = 0x03
	IsBack = 0x04
	Message = 0x06
	IDActivate = 0x07
	IDDeactivate = 0x08
	UserStat = 0x0A
	ContactNew = 0x0F
	AddIgnore = 0x11
	PingConfiguration = 0x12
	SystemMessage = 0x14
	SkinName = 0x15
	ClientHostStats = 0x16
	MassMessage = 0x17
	ConfInvite = 0x18
	ConfLogon = 0x19
	ConfDecline = 0x1A
	ConfLogoff = 0x1B
	ConfAddInvite = 0x1C
	ConfMsg = 0x1D
	FileTransfer = 0x46
	VoiceChat = 0x4A
	Notify = 0x4B
	Handshake = 0x4C
	P2PFileXfer = 0x4D
	PeerToPeer = 0x4F
	VideoChat = 0x50
	AuthResp = 0x54
	List = 0x55
	Auth = 0x57
	FriendAdd = 0x83
	FriendRemove = 0x84
	Ignore = 0x85
	ContactDeny = 0x86
	GroupRename = 0x89
	Ping = 0x8A
	ChatJoin = 0x96
	# `static var YES_CHAT_PING = 161;` 161 = 0xA1
	# Yahoo! Messenger 9.0's `desktopHub` SWF seems to list a lot of YMSG service codes and field defs in its code. :p
	ChatPing = 0xA1

class YMSGStatus(IntEnum):
	# Available/Client Request
	Available   = 0x00000000
	# BRB/Server Response
	BRB         = 0x00000001
	Busy        = 0x00000002
	# "Not at Home"/BadUsername
	NotAtHome   = 0x00000003
	NotAtDesk   = 0x00000004
	# "Not in Office"/OfflineMessage/MultiPacket
	NotInOffice = 0x00000005
	OnPhone     = 0x00000006
	OnVacation  = 0x00000007
	OutToLunch  = 0x00000008
	SteppedOut  = 0x00000009
	# Dunno when this is used, but the `PeerToPeer` service sends this according to Pidgin
	P2P         = 0x0000000B
	Invisible   = 0x0000000C
	Bad         = 0x0000000D
	Locked      = 0x0000000E
	Typing      = 0x00000016
	Custom      = 0x00000063
	Idle        = 0x000003E7
	WebLogin    = 0x5A55AA55
	Offline     = 0x5A55AA56
	LoginError  = 0xFFFFFFFF
	
	@classmethod
	def ToSubstatus(cls, ymsg_status: 'YMSGStatus') -> Substatus:
		return _ToSubstatus[ymsg_status]
	
	@classmethod
	def FromSubstatus(cls, substatus: Substatus) -> 'YMSGStatus':
		return _FromSubstatus[substatus]

_ToSubstatus = DefaultDict(Substatus.Busy, {
	YMSGStatus.Offline: Substatus.Offline,
	YMSGStatus.Available: Substatus.Online,
	YMSGStatus.BRB: Substatus.BRB,
	YMSGStatus.Busy: Substatus.Busy,
	YMSGStatus.Idle: Substatus.Idle,
	YMSGStatus.Invisible: Substatus.Invisible,
	YMSGStatus.NotAtHome: Substatus.NotAtHome,
	YMSGStatus.NotAtDesk: Substatus.NotAtDesk,
	YMSGStatus.NotInOffice: Substatus.NotInOffice,
	YMSGStatus.OnPhone: Substatus.OnPhone,
	YMSGStatus.OutToLunch: Substatus.OutToLunch,
	YMSGStatus.SteppedOut: Substatus.SteppedOut,
	YMSGStatus.OnVacation: Substatus.OnVacation,
	YMSGStatus.Locked: Substatus.Away,
	YMSGStatus.LoginError: Substatus.Offline,
	YMSGStatus.Bad: Substatus.Offline,
})
_FromSubstatus = DefaultDict(YMSGStatus.Bad, {
	Substatus.Offline: YMSGStatus.Offline,
	Substatus.Online: YMSGStatus.Available,
	Substatus.Busy: YMSGStatus.Busy,
	Substatus.Idle: YMSGStatus.Idle,
	Substatus.BRB: YMSGStatus.BRB,
	Substatus.Away: YMSGStatus.NotAtHome,
	Substatus.OnPhone: YMSGStatus.OnPhone,
	Substatus.OutToLunch: YMSGStatus.OutToLunch,
	Substatus.Invisible: YMSGStatus.Invisible,
	Substatus.NotAtHome: YMSGStatus.NotAtHome,
	Substatus.NotAtDesk: YMSGStatus.NotAtDesk,
	Substatus.NotInOffice: YMSGStatus.NotInOffice,
	Substatus.OnVacation: YMSGStatus.OnVacation,
	Substatus.SteppedOut: YMSGStatus.SteppedOut,
})

KVSType = MultiDict[bytes, bytes]
EncodedYMSG = Tuple[YMSGService, YMSGStatus, KVSType]

def build_p2p_msg_packet(bs: BackendSession, sess_id: int, p2p_dict: KVSType) -> Iterable[EncodedYMSG]:
	user_to = bs.user
	
	p2p_conn_dict = MultiDict([
		(b'4', p2p_dict.get(b'4') or b''),
		(b'5', yahoo_id(user_to.email).encode('utf-8')),
	])
	
	p2p_conn_dict.add(b'11', binascii.hexlify(struct.pack('!I', sess_id)).decode().upper().encode('utf-8'))
	if p2p_dict.get(b'12') is not None: p2p_conn_dict.add(b'12', p2p_dict.get(b'12') or b'')
	if p2p_dict.get(b'13') is not None: p2p_conn_dict.add(b'13', p2p_dict.get(b'13') or b'')
	p2p_conn_dict.add(b'49', p2p_dict.get(b'49') or b'')
	if p2p_dict.get(b'61') is not None: p2p_conn_dict.add(b'61', p2p_dict.get(b'61') or b'')
	
	yield (YMSGService.PeerToPeer, YMSGStatus.BRB, p2p_conn_dict)

def build_ft_packet(bs: BackendSession, sess_id: int, xfer_dict: KVSType) -> Iterable[EncodedYMSG]:
	user_to = bs.user
	
	ft_dict = MultiDict([
		(b'5', yahoo_id(user_to.email).encode('utf-8')),
		(b'4', xfer_dict.get(b'1') or xfer_dict.get(b'4') or b'')
	])
	
	ft_type = xfer_dict.get(b'13')
	if ft_type is not None: ft_dict.add(b'13', ft_type)
	if ft_type == b'1':
		if xfer_dict.get(b'27') is not None: ft_dict.add(b'27', xfer_dict.get(b'27') or b'')
		if xfer_dict.get(b'28') is not None: ft_dict.add(b'28', xfer_dict.get(b'28') or b'')
		
		if xfer_dict.get(b'20') is not None: ft_dict.add(b'20', xfer_dict.get(b'20') or b'')
		if xfer_dict.get(b'53') is not None: ft_dict.add(b'53', xfer_dict.get(b'53') or b'')
		if xfer_dict.get(b'14') is not None: ft_dict.add(b'14', xfer_dict.get(b'14') or b'')
		if xfer_dict.get(b'54') is not None: ft_dict.add(b'54', xfer_dict.get(b'54') or b'')
	if ft_type in (b'2',b'3'):
		# For shared files
		if xfer_dict.get(b'27') is not None: ft_dict.add(b'27', xfer_dict.get(b'27') or b'')
		if xfer_dict.get(b'53') is not None: ft_dict.add(b'53', xfer_dict.get(b'53') or b'')
		
		# For P2P messaging
		if xfer_dict.get(b'2') is not None: ft_dict.add(b'2', xfer_dict.get(b'2') or b'')
		if xfer_dict.get(b'11') is not None: ft_dict.add(b'11', binascii.hexlify(struct.pack('!I', sess_id)).decode().upper().encode('utf-8'))
		if xfer_dict.get(b'12') is not None: ft_dict.add(b'12', xfer_dict.get(b'12') or b'')
		if xfer_dict.get(b'60') is not None: ft_dict.add(b'60', xfer_dict.get(b'60') or b'')
		if xfer_dict.get(b'61') is not None: ft_dict.add(b'61', xfer_dict.get(b'61') or b'')
	if ft_type == b'5':
		if xfer_dict.get(b'54') is not None: ft_dict.add(b'54', xfer_dict.get(b'54') or b'')
	if ft_type == b'6':
		if xfer_dict.get(b'20') is not None: ft_dict.add(b'20', xfer_dict.get(b'20') or b'')
		if xfer_dict.get(b'53') is not None: ft_dict.add(b'53', xfer_dict.get(b'53') or b'')
		if xfer_dict.get(b'54') is not None: ft_dict.add(b'54', xfer_dict.get(b'54') or b'')
	if ft_type == b'9':
		if xfer_dict.get(b'53') is not None: ft_dict.add(b'53', xfer_dict.get(b'53') or b'')
	if xfer_dict.get(b'49') is not None: ft_dict.add(b'49', xfer_dict.get(b'49') or b'')
	
	yield (YMSGService.P2PFileXfer, YMSGStatus.BRB, ft_dict)

def build_http_ft_packet(bs: BackendSession, sender: str, url_path: str, upload_time: float, message: str) -> Iterable[Any]:
	user = bs.user
	
	yield (YMSGService.FileTransfer, YMSGStatus.BRB, MultiDict([
		(b'1', yahoo_id(user.email).encode('utf-8')),
		(b'5', arbitrary_encode(sender)),
		(b'4', yahoo_id(user.email).encode('utf-8')),
		(b'14', arbitrary_encode(message)),
		(b'38', str(upload_time + 86400).encode('utf-8')),
		(b'20', arbitrary_encode('http://{}{}'.format(settings.STORAGE_HOST, url_path))),
	]))

def split_to_chunks(s: str, count: int) -> List[str]:
	i = 0
	j = 0
	final = []
	
	while i < len(s):
		j += count
		if j > len(s):
			j = len(s)
		final.append(s[i:j])
		i += count
	
	return final

def yahoo_id(email: str) -> str:
	email_parts = email.split('@', 1)
	
	if len(email_parts) == 2 and email_parts[1].startswith('yahoo.com'):
		return email_parts[0]
	else:
		return email

def yahoo_id_to_uuid(backend: Backend, yahoo_id: Optional[str]) -> Optional[str]:
	if not yahoo_id:
		return None
	
	email = None # type: Optional[str]
	
	# Fun fact about foreign Yahoo! email addresses: they're just relays to the same account name but with
	# `@yahoo.com` instead of `@yahoo.*`. The server should check the address to add an entry for the `@yahoo.com`
	# account, then they can be identified.
	
	if '@' in yahoo_id:
		if not yahoo_id.endswith('@yahoo.com'):
			email = yahoo_id
		else:
			return None
	else:
		email = '{}@yahoo.com'.format(yahoo_id)
	
	return backend.util_get_uuid_from_email(email)