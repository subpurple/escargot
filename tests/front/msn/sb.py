from front.msn.misc import Err
from front.msn.msnp_ns import MSNPCtrlNS
from front.msn.msnp_sb import MSNPCtrlSB
from util.misc import Logger

from . import misc
from .mock import MSNPWriter, ANY

def test_msnp_commands(backend_with_data):
	backend = backend_with_data
	logger = Logger('MK', object(), False)
	
	# User 1 login
	w1 = MSNPWriter()
	nc1 = MSNPCtrlNS(logger, 'test', backend)
	nc1.writer = w1
	
	user1 = misc.login_msnp(nc1, 'test1@example.com', '{00000000-0000-0000-0000-000000000000}')
	nc1._m_chg('7', 'NLN', '0:0')
	
	assert backend._worklist_notify, "has unsynced notifications"
	backend._handle_worklist_notify()
	backend._worklist_notify.clear()
	
	w1.pop_message('CHG', '7', 'NLN', '0:0')
	w1.pop_message('MSG', 'Hotmail', 'Hotmail', ANY)
	# Add "test2@example.com" to FL with `ADL`
	nc1._m_adl('8', b'<ml><d n="example.com"><c n="test2" l="1" t="1" /></d></ml>')
	nc1.writer.pop_message('ADL', '8', 'OK')
	
	# User 2 login
	nc2 = MSNPCtrlNS(logger, 'test', backend)
	nc2.writer = MSNPWriter()
	
	user2 = misc.login_msnp(nc2, 'test2@example.com', '{00000000-0000-0000-0000-000000000000}')
	nc2._m_chg('7', 'NLN', '0:0')
	nc2.writer.pop_message('CHG', '7', 'NLN', '0:0')
	nc2.writer.pop_message('NLN', 'NLN', '1:test1@example.com', ANY, ANY, ANY)
	nc2.writer.pop_message('UBX', '1:test1@example.com', ANY)
	nc2.writer.pop_message('MSG', 'Hotmail', 'Hotmail', ANY)
	
	assert backend._worklist_notify, "has unsynced notifications"
	backend._handle_worklist_notify()
	backend._worklist_notify.clear()
	
	nc1.writer.pop_message('NLN', 'NLN', '1:test2@example.com', ANY, ANY, ANY)
	nc1.writer.pop_message('UBX', '1:test2@example.com', ANY)
	
	# User 1 starts convo
	nc1._m_xfr('9', 'SB')
	msg = nc1.writer.pop_message('XFR', '9', 'SB', ANY, 'CKI', ANY, ANY, ANY, ANY)
	token = msg[5]
	
	sc1 = MSNPCtrlSB(logger, 'test', backend)
	sc1.writer = MSNPWriter()
	
	sc1._m_usr('0', 'test1@example.com;{00000000-0000-0000-0000-000000000000}', token)
	sc1.writer.pop_message('USR', 0, 'OK', 'test1@example.com;{00000000-0000-0000-0000-000000000000}', ANY)
	assert sc1.bs.user.uuid == user1.uuid
	
	# MSNP18 introduces `CAL`ing yourself to get other PoPs to join; do that
	sc1._m_cal('1', 'test1@example.com')
	sc1.writer.pop_message('CAL', '1', 'RINGING', ANY)
	sc1.writer.pop_message('JOI', 'test1@example.com', ANY, ANY)
	
	sc1._m_cal('2', 'invalidhandle')
	sc1.writer.pop_message(Err.InvalidUser2, '2')
	
	sc1._m_cal('3', 'nonexistent@email.com')
	sc1.writer.pop_message(Err.PrincipalNotOnline, '3')
	
	sc1._m_cal('4', 'test2@example.com')
	sc1.writer.pop_message('CAL', '4', 'RINGING', ANY)
	
	msg = nc2.writer.pop_message('RNG', ANY, ANY, 'CKI', ANY, user1.email, ANY, ANY, ANY, ANY)
	sbsess_id = msg[1]
	token = msg[4]
	
	# User 2 joins convo
	sc2 = MSNPCtrlSB(logger, 'test', backend)
	sc2.writer = MSNPWriter()
	sc2._m_ans('0', 'test2@example.com;{00000000-0000-0000-0000-000000000000}', token, sbsess_id)
	sc2.writer.pop_message('IRO', '0', '1', '2', 'test1@example.com;{00000000-0000-0000-0000-000000000000}', ANY, ANY)
	sc2.writer.pop_message('IRO', '0', '2', '2', 'test1@example.com', ANY, ANY)
	sc2.writer.pop_message('ANS', '0', 'OK')
	sc2.writer.pop_message('JOI', 'test2@example.com', ANY, ANY)
	sc1.writer.pop_message('JOI', 'test2@example.com;{00000000-0000-0000-0000-000000000000}', ANY, ANY)
	sc1.writer.pop_message('JOI', 'test2@example.com', ANY, ANY)
	
	# User 1 sends message
	sc1._m_msg('5', 'A', b"\r\n\r\nmy message")
	sc1.writer.pop_message('ACK', '5')
	sc2.writer.pop_message('MSG', 'test1@example.com', ANY, b"\r\n\r\nmy message")
