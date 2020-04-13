from typing import Any, Dict, List
from aiohttp import web
import json

from core.backend import Backend
from core.http import render
import util.misc

TMPL_DIR = 'front/api/tmpl'

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'api', TMPL_DIR)
	
	# Actual APIs
	app.router.add_get('/api/ircChats', handle_ircchats)
	app.router.add_get('/api/stats/{service}', handle_stats_api)
	
	# API tests
	app.router.add_route('*', '/api/chats-test', handle_chat_list)

async def handle_ircchats(req: web.Request) -> web.Response:
	backend = req.app['backend'] # type: Backend
	
	result = [] # type: List[Dict[str, Any]]
	
	for chat in backend.get_chats_by_scope('irc'):
		nicks = [cs.user.email for cs in chat.get_roster_single()]
		
		result.append({
			'channel': chat.ids['irc'],
			'users': nicks,
		})
	
	return web.Response(status = 200, body = json.dumps(result))

async def handle_stats_api(req: web.Request) -> web.Response:
	backend = req.app['backend'] # type: Backend
	
	service = req.match_info['service']
	result = {} # type: Dict[str, Any]
	
	if service == 'usersActive':
		result['users_active'] = str(backend._stats.logged_in)
		return web.Response(status = 200, body = json.dumps(result))
	if service == 'messages':
		# TODO: Support message count by client ID
		
		messages_received = 0
		messages_sent = 0
		
		for stats_raw in backend._stats.by_client.values():
			from core.stats import _stats_to_json as stats_json
			stats = stats_json(stats_raw) # type: Dict[str, Any]
			
			if 'messages_received' in stats:
				messages_received += int(stats['messages_received'])
			if 'messages_sent' in stats:
				messages_sent += int(stats['messages_sent'])
		
		result['messages_received'] = str(messages_received)
		result['messages_sent'] = str(messages_sent)
		
		return web.Response(status = 200, body = json.dumps(result))
	
	return web.Response(status = 400)

async def handle_chat_list(req: web.Request) -> web.Response:
	return render(req, 'api:chats-test.html')
