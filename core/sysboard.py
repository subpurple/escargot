import asyncio
from typing import Any, Dict, Optional
from aiohttp import web
from datetime import datetime
import jinja2

from core.backend import Backend
import settings

SYSBOARD_TMPL_DIR = 'core/tmpl/sysboard'
SYSBOARD_PATH = '/sysboard'
SYSBOARD_LOGIN_PATH = SYSBOARD_PATH + '/login'
SYSBOARD_COOKIE_NAME = 'ESB'

def register(loop: asyncio.AbstractEventLoop, backend: Backend, *, devmode: bool = False) -> web.Application:
	from util.misc import AIOHTTPRunner
	
	if devmode:
		from devtls import DevTLS
		sysboard_host = '0.0.0.0'
		ssl_context = DevTLS('Escargot').create_ssl_context()
	else:
		sysboard_host = '127.0.0.1'
		ssl_context = None
	
	app = create_app(loop, backend)
	backend.add_runner(AIOHTTPRunner(sysboard_host, 4308, app, ssl_context = ssl_context, ssl_only = True))
	
	app.router.add_get(SYSBOARD_PATH, handle_sysboard_gui)
	app.router.add_post(SYSBOARD_PATH, handle_sysboard_action)
	app.router.add_get(SYSBOARD_LOGIN_PATH, handle_sysboard_login)
	app.router.add_post(SYSBOARD_LOGIN_PATH, handle_sysboard_login_verify)
	
	return app

def create_app(loop: asyncio.AbstractEventLoop, backend: Backend) -> Any:
	app = web.Application(loop = loop)
	app['backend'] = backend
	app['jinja_env'] = jinja2.Environment(
		loader = jinja2.FileSystemLoader(SYSBOARD_TMPL_DIR),
		autoescape = jinja2.select_autoescape(default = True),
	)
	
	app.on_response_prepare.append(on_response_prepare)
	
	return app

async def on_response_prepare(req: web.Request, res: web.StreamResponse) -> None:
	if not settings.DEBUG:
		return
	if not settings.DEBUG_SYSBOARD:
		return
	
	if req.path == SYSBOARD_PATH and req.method == 'POST':
		print('Pushing maintenance/system message to online users...')
	if req.path == SYSBOARD_LOGIN_PATH and req.method == 'POST':
		print('Admin being verified...')

# Sysboard HTTP entries

async def handle_sysboard_login(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	if True in (backend.maintenance_mode,backend.notify_maintenance):
		return render(req, 'unavailable.html')
	
	return (web.HTTPFound(SYSBOARD_PATH) if _validate_session(req) else render(req, 'login.html', {
		'error': False,
		'sysboard_login_path': SYSBOARD_LOGIN_PATH,
	}))

async def handle_sysboard_login_verify(req: web.Request) -> web.Response:
	body = await req.post()
	
	password = body.get('password')
	if password is None:
		return web.HTTPInternalServerError()
	
	if password == settings.SYSBOARD_PASS:
		sysboard_token = req.app['backend'].auth_service.create_token('sysboard/token', password, lifetime = 86400)
		response = web.Response(status = 302, headers = {
			'Location': SYSBOARD_PATH,
		})
		token_expiry = req.app['backend'].auth_service.get_token_expiry('sysboard/token', sysboard_token)
		response.set_cookie(
			SYSBOARD_COOKIE_NAME, sysboard_token, path = SYSBOARD_PATH,
			expires = datetime.utcfromtimestamp(token_expiry).strftime('%a, %d %b %Y %H:%M:%S GMT'),
		)
		return response
	else:
		return render(req, 'login.html', {
			'error': True,
			'sysboard_login_path': SYSBOARD_LOGIN_PATH,
		})

async def handle_sysboard_gui(req: web.Request) -> web.Response:
	backend = req.app['backend']
	
	if True in (backend.maintenance_mode,backend.notify_maintenance):
		return render(req, 'unavailable.html')
	
	return (render(req, 'index.html', {
		'sysboard_login_path': SYSBOARD_LOGIN_PATH,
		'sysboard_path': SYSBOARD_PATH,
	}) if _validate_session(req) else web.HTTPFound(SYSBOARD_LOGIN_PATH))

async def handle_sysboard_action(req: web.Request) -> web.Response:
	body = await req.post()
	backend = req.app['backend']
	
	if True in (backend.maintenance_mode,backend.notify_maintenance):
		return web.HTTPMisdirectedRequest()
	
	if not _validate_session(req):
		return web.HTTPUnauthorized()
	
	system_msg = (None if body.get('sysmsg') is None else body.get('sysmsg'))
	mt_mins_header = req.headers.get('X-Maintenance-Minutes')
	
	if mt_mins_header:
		if system_msg is not None:
			return web.HTTPInternalServerError()
		
		assert mt_mins_header
		try:
			mt_mins = int(mt_mins_header)
		except ValueError:
			return web.HTTPInternalServerError()
		
		backend.push_system_message(1, mt_mins)
	elif system_msg is not None:
		backend.push_system_message(1, -1, message = system_msg)
	else:
		return web.HTTPInternalServerError()
	
	return web.HTTPOk()

def _validate_session(req: web.Request) -> bool:
	backend = req.app['backend']
	
	sysboard_cookie = req.cookies.get(SYSBOARD_COOKIE_NAME)
	
	if sysboard_cookie is None:
		return False
	
	if backend.auth_service.get_token('sysboard/token', sysboard_cookie) is not None:
		return True
	else:
		return False

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {}))
	return web.Response(status = status, content_type = content_type, text = content)
