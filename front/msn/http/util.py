from typing import Optional, Dict, Any, Tuple

from aiohttp import web
import lxml

from core.backend import Backend, BackendSession
import settings

def render(req: web.Request, tmpl_name: str, ctxt: Optional[Dict[str, Any]] = None, status: int = 200) -> web.Response:
	if tmpl_name.endswith('.xml'):
		content_type = 'text/xml'
	else:
		content_type = 'text/html'
	tmpl = req.app['jinja_env'].get_template(tmpl_name)
	content = tmpl.render(**(ctxt or {}))
	return web.Response(status = status, content_type = content_type, text = content)

async def preprocess_soap(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	mspauth = False
	
	body = await req.read()
	root = parse_xml(body)
	
	token = find_element(root, 'TicketToken')
	if token is None:
		token = req.cookies.get('MSPAuth')
		if token is None:
			token = parse_cookies(req.headers.get('Cookie')).get('MSPAuth')
		if token is not None:
			mspauth = True
	if token is None:
		raise web.HTTPInternalServerError()
		
	if token[0:2] == 't=':
		token = token[2:22]
	elif mspauth:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	backend_sess = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	action = find_element(root, 'Body/*[1]')
	if settings.DEBUG and settings.DEBUG_MSNP: print('Action: {}'.format(get_tag_localname(action)))
	
	return header, action, backend_sess, token

def get_tag_localname(elm: Any) -> str:
	return lxml.etree.QName(elm.tag).localname

def find_element(xml: Any, query: str) -> Any:
	thing = xml.find('.//{*}' + query.replace('/', '/{*}'))
	if isinstance(thing, lxml.objectify.StringElement):
		thing = str(thing)
	elif isinstance(thing, lxml.objectify.BoolElement):
		thing = bool(thing)
	return thing

def unknown_soap(req: web.Request, header: Any, action: Any, *, expected: bool = False) -> web.Response:
	action_str = get_tag_localname(action)
	if not expected and settings.DEBUG:
		print("Unknown SOAP:", action_str)
		print(xml_to_string(header))
		print(xml_to_string(action))
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

def xml_to_string(xml: Any) -> str:
	return lxml.etree.tostring(xml, pretty_print = True).decode('utf-8')

def bool_to_str(b: bool) -> str:
	return 'true' if b else 'false'

def parse_cookies(cookie_string: Optional[str]) -> Dict[str, Any]:
	cookie_dict = {}
	cookie_data = None
	
	if not cookie_string:
		return {}
	
	cookies = cookie_string.split(';')
	
	for cookie in cookies:
		if not cookie: continue
		cookie_kv = cookie.split('=', 1)
		if len(cookie_kv) == 2:
			cookie_data = cookie_kv[1]
		cookie_dict[cookie_kv[0]] = cookie_data
	
	return cookie_dict
