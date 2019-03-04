import asyncio
from typing import Any, Dict, Optional
from aiohttp import web
import json

from core.backend import Backend
from core.http import render
import util.misc

TMPL_DIR = 'front/api/tmpl'

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'api', TMPL_DIR)
	
	app.router.add_get('/api/ircChats', handle_ircchats)
	app.router.add_route('*', '/api/chats-test.html', handle_chat_list)

async def handle_ircchats(req: web.Request) -> web.Response:
	backend = req.app['backend'] # type: Backend
	
	result = {} # type: Dict[str, Dict[str, Any]]
	
	for chat in backend.get_chats_by_scope('irc'):
		nicks = [cs.user.email for cs in chat.get_roster_single()]
		
		result[chat.ids['irc']] = {
			'users': nicks,
		}
	
	return web.Response(status = 200, body = json.dumps(result))

async def handle_chat_list(req: web.Request) -> web.Response:
	return render(req, 'api:chats-test.html')