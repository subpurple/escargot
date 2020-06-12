from front.msn.msnp_ns import MSNPCtrlNS
from front.msn.misc import Err
from core.models import Service, Lst, Substatus

from . import misc
from .mock import MSNPWriter, Logger, ANY

def test_msnp_commands(backend_with_data) -> None:
	backend = backend_with_data
	logger = Logger('MK', object(), False)
	
	email = 'test1@example.com'
	
	w1 = MSNPWriter()
	nc1 = MSNPCtrlNS(logger, 'test', backend)
	nc1.writer = w1
	
	# Login on first endpoint
	
	user = misc.login_msnp(nc1, 'test1@example.com', '{00000000-0000-0000-0000-000000000000}')
	
	# Group/Contact Management
	
	# Add "doesnot@exist.com" to FL with `ADL` (triggers error)
	nc1._m_adl('7', b'<ml><d n="exist.com"><c n="doesnot" l="1" t="1" /></d></ml>')
	w1.pop_message(Err.InvalidUser2, '7')
	# Add "test2@example.com" to FL with `ADL`
	nc1._m_adl('8', b'<ml><d n="example.com"><c n="test2" l="1" t="1" /></d></ml>')
	w1.pop_message('ADL', '8', 'OK')
	ctc = None
	for ctc in user.detail.contacts.values():
		if ctc.head.email == 'test2@example.com':
			break
	assert ctc and ctc.head.email == 'test2@example.com'
	assert ctc.lists | Lst.FL
	#assert not ctc.groups
	#nc1._l_adc(17, 'FL', 'C={}'.format(uuid), group_uuid)
	#w1.pop_message('ADC', 17, 'FL', 'C={}'.format(uuid), group_uuid)
	#assert user.detail.contacts[uuid].groups == { group_uuid }
	
	assert backend._worklist_sync_db, "has unsynced data"
	backend._sync_db_impl()
	assert not backend._worklist_sync_db, "db was synced"
	
	# Add "test2@example.com" to BL with `ADL`
	nc1._m_adl('9', b'<ml><d n="example.com"><c n="test2" l="4" t="1" /></d></ml>')
	w1.pop_message('ADL', '9', 'OK')
	assert ctc.lists & Lst.BL
	# Remove "test2@example.com" from BL with `RML`
	nc1._m_rml('10', b'<ml><d n="example.com"><c n="test2" l="4" t="1" /></d></ml>')
	w1.pop_message('RML', '10', 'OK')
	assert not (ctc.lists & Lst.BL)
	#nc1._l_rem(20, 'FL', uuid, 'notvalidgroupid')
	#w1.pop_message(Err.GroupInvalid, 20)
	#nc1._l_rem(21, 'FL', uuid, group_uuid)
	#w1.pop_message('REM', 21, 'FL', uuid, group_uuid)
	#assert not user.detail.contacts[uuid].groups
	# Remove "notvalid@email.com" from FL with `RML`; this will return an `OK` anyway as Messenger will possibly already remove contacts with the `ABContactDelete` SOAP function beforehand and we want to avoid any conflicts between that and the NS.
	nc1._m_rml('11', b'<ml><d n="email.com"><c n="notvalid" l="1" t="1" /></d></ml>')
	w1.pop_message('RML', '11', 'OK')
	# Remove "test2@example.com" from FL with `RML`
	nc1._m_rml('12', b'<ml><d n="example.com"><c n="test2" l="1" t="1" /></d></ml>')
	w1.pop_message('RML', '12', 'OK')
	assert ctc.head.uuid not in user.detail.contacts
	
	'''nc1._l_adg(8, 'x' * 100, 'ignored')
	w1.pop_message(Err.GroupNameTooLong, 8)
	nc1._l_adg(9, "New Group")
	msg = w1.pop_message('ADG', 9, "New Group", ANY, ANY)
	assert user.detail.groups[msg[3]].name == msg[2]
	nc1._l_rmg(10, "New%20Group")
	w1.pop_message('RMG', 10, 1, msg[3])
	assert msg[3] not in user.detail.groups
	
	nc1._l_rmg(11, '0')
	w1.pop_message(Err.GroupZeroUnremovable, 11)
	nc1._l_rmg(12, 'blahblahblah')
	w1.pop_message(Err.GroupInvalid, 12)
	
	nc1._l_adg(13, "Group Name")
	msg = w1.pop_message('ADG', 13, "Group Name", ANY, ANY)
	group_uuid = msg[3]
	assert user.detail.groups[group_uuid].name == msg[2]
	nc1._l_reg(14, group_uuid, "New Group Name", 'ignored')
	w1.pop_message('REG', 14, 1, "New Group Name", group_uuid, ANY)
	assert user.detail.groups[group_uuid].name == "New Group Name"
	
	'''
	
	# TODO: MPoP and Circle stuff
	
	# Misc
	
	nc1._m_png()
	w1.pop_message('QNG', ANY)
	
	nc1._m_url('6', 'blah')
	w1.pop_message('URL', '6', ANY, ANY, ANY)
	
	nc1._m_uux('7', b'<Data><PSM>my message</PSM><CurrentMedia>song name</CurrentMedia></Data>')
	w1.pop_message('UUX', '7', ANY)
	assert user.status.message == "my message"
	assert user.status.media == "song name"
	
	nc1._m_blp('25', 'AL')
	w1.pop_message('BLP', '25', 'AL')
	
	nc1._m_chg('26', 'NLN', '0:0')
	w1.pop_message('CHG', '26', 'NLN', '0:0')
	w1.pop_message('MSG', 'Hotmail', 'Hotmail', ANY)
	assert user.status.substatus == Substatus.Online
	
	nc1._m_rea('27', 'test1@example.com', "My Name")
	w1.pop_message(Err.CommandDisabled, 27)
	
	nc1._m_snd('28', 'email@blah.com', '0x0409')
	w1.pop_message('SND', '28', 'OK')
	
	nc1._m_prp('29', 'MFN', "My Name")
	w1.pop_message('PRP', '29', 'MFN', "My Name")
	assert user.status.name == "My Name"
	
	nc1._m_xfr('30', 'SB')
	w1.pop_message('XFR', '30', 'SB', ANY, 'CKI', ANY, ANY, ANY, ANY)
