from typing import Any, Dict, Optional, Tuple
from aiohttp import web
import asyncio
from markupsafe import Markup
from urllib.parse import unquote, unquote_plus, quote
from pathlib import Path
import shutil

from core.backend import Backend, BackendSession
from core.models import Contact, Substatus
import util.misc
from util.hash import gen_salt
from .ymsg_ctrl import _try_decode_ymsg
from .misc import YMSGService
import time

YAHOO_TMPL_DIR = 'front/ymsg/tmpl'
# https://github.com/ifwe/digsby/blob/f5fe00244744aa131e07f09348d10563f3d8fa99/digsby/src/yahoo/yahooutil.py#L33
FILE_STORE_PATH = '/storage/file/{filename}'
_tasks_by_token = {} # type: Dict[str, asyncio.Task[None]]

def register(app: web.Application, *, devmode: bool = False) -> None:
	util.misc.add_to_jinja_env(app, 'ymsg', YAHOO_TMPL_DIR)
	
	# Yahoo! Insider
	app.router.add_get('/ycontent/', handle_insider_ycontent)
	
	# Yahoo! Chat/Ads
	app.router.add_get('/us.yimg.com/i/msgr/chat/conf-banner.html', handle_chat_banad)
	app.router.add_get('/c/msg/tabs.html', handle_chat_tabad)
	app.router.add_get('/etc/yahoo-tab-ad', handle_chat_tabad)
	app.router.add_get('/c/msg/chat.html', handle_chat_notice)
	app.router.add_get('/c/msg/alerts.html', handle_chat_alertad)
	app.router.add_get('/etc/yahoo-placeholder', handle_placeholder)
	
	if devmode:
		app.router.add_static('/static', YAHOO_TMPL_DIR + '/static')
	
	# Yahoo!'s redirector to cookie-based services
	#app.router.add_get('/config/reset_cookies', handle_cookies_redirect)
	
	# Yahoo!'s redirect service (rd.yahoo.com)
	app.router.add_get('/messenger/search/', handle_rd_yahoo)
	app.router.add_get('/messenger/client/', handle_rd_yahoo)
	
	# Yahoo HTTP file transfer fallback
	app.router.add_post('/notifyft', handle_ft_http)
	app.router.add_get(FILE_STORE_PATH, handle_yahoo_filedl)

async def handle_insider_ycontent(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	yab_received = False
	yab_set = False
	config_xml = []
	for query_xml in req.query.keys():
		# Ignore any `chatroom_##########` requests for now
		if query_xml in IGNORED_QUERIES or query_xml.startswith('chatroom_'): continue
		if query_xml in ('ab2','addab2'):
			(_, bs) = _parse_cookies(req, backend)
			if bs is not None:
				user = bs.user
				detail = user.detail
				if detail is not None:
					ab2_tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.ab2.xml')
					if query_xml == 'ab2':
						if yab_received or yab_set: continue
						ctcs = detail.contacts.values()
						
						records = []
						
						for ctc in ctcs:
							records.append(_gen_yab_record(ctc))
						config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup('\n'.join(records))))
					if query_xml == 'addab2':
						edit_mode = False
						
						if yab_set or yab_received: continue
						if req.query.get('ee') is '1' and req.query.get('ow') is '1':
							edit_mode = True
						
						if edit_mode:
							if req.query.get('id') is None:
								continue
							
							target_ctc = None
							
							entry_id = str(req.query['id'])
							for ctc in detail.contacts.values():
								if ctc.detail.index_id == entry_id:
									target_ctc = ctc
							
							if not target_ctc:
								continue
							
							if req.query.get('pp') is not None:
								if str(req.query['pp']) not in ('0','1','2'):
									continue
							
							new_first_name = req.query.get('fn')
							new_last_name = req.query.get('ln')
							# Yahoo! will set the email/YID as the first name when editing contact details;
							# if new_first_name == email and last name isn't set, don't set first name
							if new_first_name != target_ctc.head.email and new_last_name:
								target_ctc.detail.first_name = new_first_name
							target_ctc.detail.last_name = new_last_name
							target_ctc.detail.nickname = req.query.get('nn')
							target_ctc.detail.personal_email = req.query.get('e')
							target_ctc.detail.home_phone = req.query.get('hp')
							target_ctc.detail.work_phone = req.query.get('wp')
							target_ctc.detail.mobile_phone = req.query.get('mb')
							
							backend._mark_modified(user)
						else:
							continue
						
						config_xml.append(ab2_tmpl.render(epoch = round(time.time()), records = Markup(_gen_yab_record(target_ctc))))
			continue
		tmpl = req.app['jinja_env'].get_template('ymsg:Yinsider/Yinsider.' + query_xml + '.xml')
		config_xml.append(tmpl.render())
	
	return render(req, 'ymsg:Yinsider/Yinsider.xml', {
		'epoch': round(time.time()),
		'configxml': Markup('\n'.join(config_xml)),
	})

# 'intl', 'os', 'ver', 'fn', 'ln', 'yid', 'nn', 'e', 'hp', 'wp', 'mp', 'pp', 'ee',
# 'ow', and 'id' are NOT queries to retrieve config XML files;
# 'getwc' and 'getgp' are undocumented as of now
# Other queries most likely are just not implemented
IGNORED_QUERIES = {
	'intl', 'os', 'ver',
	'imv', 'sms', 'getimv', 'getwc', 'getgp',
	'fn', 'ln', 'yid',
	'nn', 'e', 'hp',
	'wp', 'mb', 'pp',
	'ee', 'ow', 'id',
}

def _gen_yab_record(ctc: Contact) -> str:
	fname = None
	lname = None
	nname = None
	email = None
	hphone = None
	wphone = None
	mphone = None
	if ctc.detail.first_name is not None:
		fname = ' fname="{}"'.format(ctc.detail.first_name)
	if ctc.detail.last_name is not None:
		lname = ' lname="{}"'.format(ctc.detail.last_name)
	if ctc.detail.nickname is not None:
		nname = ' nname="{}"'.format(ctc.detail.nickname)
	if ctc.detail.personal_email is not None:
		email = ' email="{}"'.format(ctc.detail.personal_email)
	if ctc.detail.home_phone is not None:
		hphone = ' hphone="{}"'.format(ctc.detail.home_phone)
	if ctc.detail.work_phone is not None:
		wphone = ' wphone="{}"'.format(ctc.detail.work_phone)
	if ctc.detail.mobile_phone is not None:
		mphone = ' mphone="{}"'.format(ctc.detail.mobile_phone)
	
	return '<record userid="{yid}"{fname}{lname}{nname}{email}{hphone}{wphone}{mphone} dbid="{contact_id}"/>'.format(
		yid = ctc.head.username,
		fname = fname or '', lname = lname or '', nname = nname or '',
		email = email or '', hphone = hphone or '', wphone = wphone or '', mphone = mphone or '',
		contact_id = ctc.detail.index_id,
	)

async def handle_chat_banad(req: web.Request) -> web.Response:
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
	#return render(req, 'ymsg:placeholders/generic.html')
	return web.HTTPFound('http://escargot.log1p.xyz/etc/yahoo-chat-pane')

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
#	tok_exp_y = backend.auth_service.get_token_expiry('ymsg/cookie', y)
#	y_expiry = datetime.datetime.utcfromtimestamp(tok_exp_y).strftime('%a, %d %b %Y %H:%M:%S GMT')
#	tok_exp_t = backend.auth_service.get_token_expiry('ymsg/cookie', t)
#	t_expiry = datetime.datetime.utcfromtimestamp(tok_exp_t).strftime('%a, %d %b %Y %H:%M:%S GMT') 
#	
#	# TODO: Replace '.yahoo.com' with '.log1p.xyz' when patched Yahoo! Messenger files are released.
#	domain = ('yahooloopback.log1p.xyz' if settings.DEBUG else settings.TARGET_HOST)
#	resp.set_cookie('Y', y, path = '/', expires = y_expiry, domain = domain)
#	resp.set_cookie('T', t, path = '/', expires = t_expiry, domain = domain)
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
		return web.HTTPInternalServerError(text = '')
	
	try:
		# check version and vendorId
		if y_ft_pkt[1] > 16 or y_ft_pkt[2] not in (0, 100):
			return web.HTTPInternalServerError(text = '')
	except Exception:
		return web.HTTPInternalServerError(text = '')
	
	if y_ft_pkt[0] is not YMSGService.FileTransfer:
		return web.HTTPInternalServerError(text = '')
	
	ymsg_data = y_ft_pkt[5]
	
	yahoo_id_sender = util.misc.arbitrary_decode(ymsg_data.get(b'0') or b'')
	(yahoo_id, bs) = _parse_cookies(req, backend)
	if None in (bs,yahoo_id):
		return web.HTTPInternalServerError(text = '')
	assert bs is not None
	
	yahoo_id_recipient = util.misc.arbitrary_decode(ymsg_data.get(b'5') or b'')
	recipient_uuid = backend.util_get_uuid_from_username(yahoo_id_recipient)
	if recipient_uuid is None:
		return web.HTTPInternalServerError(text = '')
	recipient_head = backend._load_user_record(recipient_uuid)
	if recipient_head is None or recipient_head.status.substatus is Substatus.Offline:
		return web.HTTPInternalServerError(text = '')
	
	message = util.misc.arbitrary_decode(ymsg_data.get(b'14') or b'')
	
	file_path_raw = ymsg_data.get(b'27') # type: Optional[bytes]
	file_len = util.misc.arbitrary_decode(ymsg_data.get(b'28') or b'0')
	
	# https://github.com/ifwe/digsby/blob/master/digsby/src/yahoo/yfiletransfer.py#L7
	# Looks like the HTTP file transfer server had its own size limits (10 MB)
	if file_path_raw is None or str(len(stream)) != file_len or len(stream) > (2 ** 20):
		return web.HTTPInternalServerError(text = '')
	
	file_path = util.misc.arbitrary_decode(file_path_raw)
	
	try:
		filename = Path(file_path).name
	except:
		return web.HTTPInternalServerError(text = '')
	
	token = gen_salt(length = 30)
	path = _get_tmp_file_storage_path(token)
	path.mkdir(exist_ok = True, parents = True)
	
	file_tmp_path = path / unquote_plus(filename)
	file_tmp_path.write_bytes(stream)
	
	upload_time = time.time()
	
	expiry_task = req.app.loop.create_task(_store_tmp_file_until_expiry(file_tmp_path))
	_tasks_by_token[token] = expiry_task
	
	for bs_other in bs.backend._sc.iter_sessions():
		if bs_other.user.uuid != recipient_uuid:
			continue
		bs_other.evt.ymsg_on_sent_ft_http(
			yahoo_id_sender, '{}?{}'.format(FILE_STORE_PATH.format(filename = quote(file_tmp_path.name)), token),
			upload_time, message,
		)
	
	bs.evt.ymsg_on_upload_file_ft(yahoo_id_recipient, message)
	
	return web.HTTPOk(text = '')

async def _store_tmp_file_until_expiry(path: Path) -> None:
	await asyncio.sleep(86400)
	# When a day passes, delete the file (unless it has already been deleted by
	# the downloader handler; it will cancel the according task then)
	shutil.rmtree(str(path), ignore_errors = True)

async def handle_yahoo_filedl(req: web.Request) -> web.Response:
	filename = req.match_info['filename']
	token = None
	query_keys = list(req.query.keys())
	if query_keys:
		token = list(req.query.keys())[0]
	
	if token is None:
		return web.HTTPNotFound(text = '')
	
	file_storage_path = _get_tmp_file_storage_path(token)
	file_path = file_storage_path / unquote(filename)
	try:
		file_stream = file_path.read_bytes()
	except FileNotFoundError:
		return web.HTTPNotFound(text = '')
	# Only delete temporary file if request is specifically `GET`
	if req.method == 'GET':
		_tasks_by_token[token].cancel()
		del _tasks_by_token[token]
		shutil.rmtree(file_storage_path, ignore_errors = True)
	return web.Response(status = 200, headers = {
		'Content-Disposition': 'attachment; filename="{}"'.format(filename),
	}, body = file_stream)

def _get_tmp_file_storage_path(token: str) -> Path:
	return Path('storage/file') / token

def _parse_cookies(
	req: web.Request, backend: Backend, y: Optional[str] = None, t: Optional[str] = None,
) -> Tuple[Optional[str], Optional[BackendSession]]:
	cookies = req.cookies
	
	if None in (y,t):
		y_cookie = cookies.get('Y')
		t_cookie = cookies.get('T')
	else:
		y_cookie = y
		t_cookie = t
	
	return (backend.auth_service.get_token('ymsg/cookie', y_cookie or ''), backend.auth_service.get_token('ymsg/cookie', t_cookie or ''))

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {})).replace('\n', '\r\n')
	return web.Response(status = status, content_type = content_type, text = content)
