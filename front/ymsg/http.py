from typing import Any, Dict, List, Optional, Tuple
from aiohttp import web
import asyncio
from markupsafe import Markup
from urllib.parse import unquote, unquote_plus, quote
from pathlib import Path
import datetime
import shutil
import re

from core.backend import Backend, BackendSession
import util.misc
from .ymsg_ctrl import _try_decode_ymsg
from .misc import YMSGService, yahoo_id_to_uuid, yahoo_id
import time

YAHOO_TMPL_DIR = 'front/ymsg/tmpl'
_tasks_by_uuid_store = {} # type: Dict[str, asyncio.Task[None]]

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'ymsg', YAHOO_TMPL_DIR)
	
	# Yahoo! Insider
	app.router.add_get('/ycontent/', handle_insider_ycontent)
	
	# Yahoo! Chat/Ads
	app.router.add_route('*', '/us.yimg.com/i/msgr/chat/conf-banner.html', handle_chat_banad)
	app.router.add_route('*', '/c/msg/tabs.html', handle_chat_tabad)
	app.router.add_route('*', '/etc/yahoo-tab-ad', handle_chat_tabad)
	app.router.add_route('*', '/c/msg/chat.html', handle_chat_notice)
	app.router.add_route('*', '/c/msg/alerts.html', handle_chat_alertad)
	app.router.add_route('*', '/etc/yahoo-placeholder', handle_placeholder)
	app.router.add_static('/etc/img', YAHOO_TMPL_DIR + '/placeholders/img')
	
	# Yahoo!'s redirector to cookie-based services
	#app.router.add_route('*', '/config/reset_cookies', handle_cookies_redirect)
	
	# Yahoo!'s redirect service (rd.yahoo.com)
	app.router.add_get('/messenger/search/', handle_rd_yahoo)
	app.router.add_get('/messenger/client/', handle_rd_yahoo)
	
	# Yahoo HTTP file transfer fallback
	app.router.add_post('/notifyft', handle_ft_http)
	app.router.add_get('/tmp/file/{file_id}/{filename}', handle_yahoo_filedl)

async def handle_insider_ycontent(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	yab_received = False
	yab_set = False
	config_xml = []
	for query_xml in req.query.keys():
		# Ignore any `chatroom_##########` requests for now
		if query_xml in UNUSED_QUERIES or query_xml.startswith('chatroom_'): continue
		if query_xml in ('ab2','addab2'):
			(_, bs) = _parse_cookies(req, backend)
			if bs is not None:
				user = bs.user
				detail = user.detail
				if detail is not None:
					ab2_tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.ab2.xml')
					if query_xml == 'ab2':
						if yab_received or yab_set: continue
						tpl = backend.user_service.get_ab_contents(user)
						if tpl is not None:
							_, _, _, ab_contacts = tpl
							ab_ctcs = [ab_contact for ab_contact in ab_contacts.values() if ab_contact.type == 'Regular']
							records = []
							
							for ab_ctc in ab_ctcs:
								records.append(_gen_yab_record(ab_ctc))
							config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup('\n'.join(records))))
					if query_xml == 'addab2':
						edit_mode = False
						email_member = None
						
						if yab_set or yab_received: continue
						if req.query.get('ee') is '1' and req.query.get('ow') is '1':
							edit_mode = True
						
						if edit_mode:
							if req.query.get('id') is None:
								continue
							
							entry_id = str(req.query['id'])
							ab_ctc = backend.user_service.ab_get_entry_by_id(entry_id, user)
						else:
							yid = req.query.get('yid')
							if yid is None: continue
							
							if '@' in yid:
								if not yid.endswith('@yahoo.com'):
									email_member = yid
								else:
									email_member = None
							else:
								email_member = '{}@yahoo.com'.format(yid)
							
							if email_member is None:
								continue
							entry_uuid = backend.util_get_uuid_from_email(email_member)
							if entry_uuid is None:
								continue
							
							ab_ctc = backend.user_service.ab_get_entry_by_email(email_member, 'Regular', user)
							if ab_ctc is not None:
								continue
							
							ab_ctc = AddressBookContact(
								'Regular', backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), email_member, '', set(),
								member_uuid = email_member, is_messenger_user = True,
							)
						if req.query.get('pp') is not None:
							if str(req.query['pp']) not in ('0','1','2'):
								continue
						ab_ctc.first_name = req.query.get('fn')
						ab_ctc.last_name = req.query.get('ln')
						ab_ctc.nickname = req.query.get('nn')
						ab_ctc.personal_email = req.query.get('e')
						ab_ctc.home_phone = req.query.get('hp')
						ab_ctc.work_phone = req.query.get('wp')
						ab_ctc.mobile_phone = req.query.get('mb')
						
						await backend.user_service.mark_ab_modified_async({ 'contacts': [ab_ctc] }, user)
						
						config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup(_gen_yab_record(ab_ctc))))
			continue
		tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.' + query_xml + '.xml')
		config_xml.append(tmpl.render())
	
	return render(req, 'ymsg:Yinsider/Yinsider.xml', {
		'epoch': round(time.time()),
		'configxml': Markup('\n'.join(config_xml)),
	})

# 'intl', 'os', 'ver', 'fn', 'ln', 'yid', 'nn', 'e', 'hp', 'wp', 'mp', 'pp', 'ee', 'ow', and 'id' are NOT queries to retrieve config XML files;
# 'getwc' and 'getgp' are unsure of their use
UNUSED_QUERIES = {
	'intl', 'os', 'ver',
	'getimv', 'getwc', 'getgp',
	'fn', 'ln', 'yid',
	'nn', 'e', 'hp',
	'wp', 'mb', 'pp',
	'ee', 'ow', 'id',
}

def _gen_yab_record(ab_ctc: AddressBookContact) -> str:
	fname = None
	lname = None
	nname = None
	email = None
	hphone = None
	wphone = None
	mphone = None
	if ab_ctc.first_name is not None:
		fname = ' fname="{}"'.format(ab_ctc.first_name)
	if ab_ctc.last_name is not None:
		lname = ' lname="{}"'.format(ab_ctc.last_name)
	if ab_ctc.nickname is not None:
		nname = ' nname="{}"'.format(ab_ctc.nickname)
	if ab_ctc.personal_email is not None:
		email = ' email="{}"'.format(ab_ctc.personal_email)
	if ab_ctc.home_phone is not None:
		hphone = ' hphone="{}"'.format(ab_ctc.home_phone)
	if ab_ctc.work_phone is not None:
		wphone = ' wphone="{}"'.format(ab_ctc.work_phone)
	if ab_ctc.mobile_phone is not None:
		mphone = ' mphone="{}"'.format(ab_ctc.mobile_phone)
	
	return '<record userid="{yid}"{fname}{lname}{nname}{email}{hphone}{wphone}{mphone} dbid="{contact_id}"/>'.format(
		yid = yahoo_id(ab_ctc.email),
		fname = fname or '', lname = lname or '', nname = nname or '',
		email = email or '', hphone = hphone or '', wphone = wphone or '', mphone = mphone or '',
		contact_id = ab_ctc.id,
	)

async def handle_chat_banad(req: web.Request) -> web.Response:
	query = req.query
	
	return render(req, 'ymsg:placeholders/banad.html')

async def handle_chat_tabad(req: web.Request) -> web.Response:
	query = req.query
	
	return render(req, 'ymsg:placeholders/adsmall.html', {
		'adtitle': 'banner ad',
		'spaceid': (query.get('spaceid') or 0),
	})

async def handle_chat_alertad(req: web.Request) -> web.Response:
	query = req.query
	
	return render(req, 'ymsg:placeholders/adsmall.html', {
		'adtitle': 'alert ad usmsgr',
		'spaceid': (query.get('spaceid') or 0),
	})

async def handle_placeholder(req: web.Request) -> web.Response:
	return render(req, 'ymsg:placeholders/generic.html')

async def handle_chat_notice(req: web.Request) -> web.Response:
	return render(req, 'ymsg:placeholders/chatpane.html')

async def handle_rd_yahoo(req: web.Request) -> web.Response:
	return web.HTTPFound(req.query_string.replace(' ', '+'))

#async def handle_cookies_redirect(req: web.Request) -> web.Response:
#	# Retreive the `Y` and `T` cookies.
#	
#	query = req.query
#	backend = req.app['backend']
#	
#	y_cookie = query.get('.y')
#	t_cookie = query.get('.t')
#	
#	(yahoo_id, bs) = _parse_cookies(req, backend, y = y_cookie[2:], t = t_cookie[2:])
#	if bs is None or yahoo_id is None:
#		raise web.HTTPInternalServerError
#	
#	redir_to = query.get('.done')
#	
#	return _redir_with_auth_cookies(redir_to, y_cookie[2:], t_cookie[2:], backend)

#def _redir_with_auth_cookies(loc: str, y: str, t: str, backend: Backend) -> web.Response:
#	resp = web.Response(status = 302, headers = {
#		'Location': loc,
#	})
#	
#	y_expiry = datetime.datetime.utcfromtimestamp(backend.auth_service.get_token_expiry('ymsg/cookie', y)).strftime('%a, %d %b %Y %H:%M:%S GMT')
#	t_expiry = datetime.datetime.utcfromtimestamp(backend.auth_service.get_token_expiry('ymsg/cookie', t)).strftime('%a, %d %b %Y %H:%M:%S GMT') 
#	
#	# TODO: Replace '.yahoo.com' with '.log1p.xyz' when patched Yahoo! Messenger files are released.
#	resp.set_cookie('Y', y, path = '/', expires = y_expiry, domain = '.yahoo.com')
#	resp.set_cookie('T', t, path = '/', expires = t_expiry, domain = '.yahoo.com')
#	
#	return resp

async def handle_ft_http(req: web.Request) -> web.Response:
	body = await req.read()
	
	# Look for incomplete key-value field `29`
	stream_loc = body.find(b'29\xC0\x80')
	stream = body[(stream_loc + 4):]
	
	# Parse the rest of the YMSG packet
	raw_ymsg_data = body[:stream_loc]
	
	# Now change the length field as fit to get the YMSG parser to gobble it up
	import struct
	
	raw_ymsg_part_pre = raw_ymsg_data[0:8]
	raw_ymsg_part_post = raw_ymsg_data[10:]
	
	raw_ymsg_data = raw_ymsg_part_pre + struct.pack('!H', len(raw_ymsg_part_post[10:])) + raw_ymsg_part_post
	
	backend = req.app['backend']
	
	try:
		y_ft_pkt = _try_decode_ymsg(raw_ymsg_data, 0)[0]
	except Exception:
		raise web.HTTPInternalServerError
	
	try:
		# check version and vendorId
		if y_ft_pkt[1] > 16 or y_ft_pkt[2] not in (0, 100):
			raise web.HTTPInternalServerError
	except Exception:
		raise web.HTTPInternalServerError
	
	if y_ft_pkt[0] is not YMSGService.FileTransfer:
		raise web.HTTPInternalServerError
	
	ymsg_data = y_ft_pkt[5]
	
	yahoo_id_sender = util.misc.arbitrary_decode(ymsg_data.get(b'0') or b'')
	(yahoo_id, bs) = _parse_cookies(req, backend)
	if bs is None or yahoo_id is None or not yahoo_id_to_uuid(backend, yahoo_id):
		raise web.HTTPInternalServerError
	
	yahoo_id_recipient = util.misc.arbitrary_decode(ymsg_data.get(b'5') or b'')
	recipient_uuid = yahoo_id_to_uuid(backend, yahoo_id_recipient)
	if recipient_uuid is None:
		raise web.HTTPInternalServerError
	
	message = util.misc.arbitrary_decode(ymsg_data.get(b'14') or b'')
	
	file_path_raw = ymsg_data.get(b'27') # type: Optional[bytes]
	file_len = util.misc.arbitrary_decode(ymsg_data.get(b'28') or b'0')
	
	if file_path_raw is None or str(len(stream)) != file_len or len(stream) > (2 * (1000 ** 3)):
		raise web.HTTPInternalServerError
	
	file_path = util.misc.arbitrary_decode(file_path_raw)
	
	try:
		filename = Path(file_path).name
	except:
		raise web.HTTPInternalServerError
	
	path = _get_tmp_file_storage_path()
	path.mkdir(exist_ok = True)
	
	file_tmp_path = path / unquote_plus(filename)
	file_tmp_path.write_bytes(stream)
	
	upload_time = time.time()
	
	expiry_task = req.app.loop.create_task(_store_tmp_file_until_expiry(path))
	_tasks_by_uuid_store[file_tmp_path.name[12:]] = expiry_task
	
	for bs_other in bs.backend._sc.iter_sessions():
		if bs_other.user.uuid == recipient_uuid:
			bs_other.evt.ymsg_on_sent_ft_http(yahoo_id_sender, '/tmp/file/{}'.format(file_tmp_path.name[12:]), upload_time, message)
	
	# TODO: Sending HTTP FT acknowledgement crahes Yahoo! Messenger, and ultimately freezes the computer. Ignore for now.
	#bs.evt.ymsg_on_upload_file_ft(yahoo_id_recipient, message)
	
	raise web.HTTPOk

async def _store_tmp_file_until_expiry(file_storage_path: Path) -> None:
	await asyncio.sleep(86400)
	# When a day passes, delete the file (unless it has already been deleted by the downloader handler; it will cancel the according task then)
	shutil.rmtree(str(file_storage_path), ignore_errors = True)

async def handle_yahoo_filedl(req: web.Request) -> web.Response:
	file_id = req.match_info['file_id']
	
	if req.method != 'GET':
		raise web.HTTPMethodNotAllowed
	
	file_storage_path = _get_tmp_file_storage_path(id = file_id)
	filename = req.match_info['filename']
	file_path = file_storage_path / unquote_plus(filename)
	try:
		file_stream = file_path.read_bytes()
	except FileNotFoundError:
		raise web.HTTPNotFound
	_tasks_by_uuid_store[file_id].cancel()
	del _tasks_by_uuid_store[file_id]
	shutil.rmtree(file_storage_path, ignore_errors = True)
	return web.HTTPOk(body = file_stream)

def _get_tmp_file_storage_path(id: Optional[str] = None) -> Path:
	if not id:
		# Call `gen_uuid()` two times to make things more random =)
		id = util.misc.gen_uuid()[0:6] + util.misc.gen_uuid()[-10:]
	return Path('storage/yfs') / id

def _parse_cookies(req: web.Request, backend: Backend, y: Optional[str] = None, t: Optional[str] = None) -> Tuple[Optional[str], Optional[BackendSession]]:
	cookies = req.cookies
	
	if None in (y,t):
		y_cookie = cookies.get('Y')
		t_cookie = cookies.get('T')
	else:
		y_cookie = y
		t_cookie = t
	
	return (backend.auth_service.get_token('ymsg/cookie', y_cookie), backend.auth_service.get_token('ymsg/cookie', t_cookie))

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {})).replace('\n', '\r\n')
	return web.Response(status = status, content_type = content_type, text = content)
