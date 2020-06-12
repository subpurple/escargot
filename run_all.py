from typing import Any, Type
from types import TracebackType
import sys
from core.conn import Conn
from core.auth import AuthService, LoginAuthService
from core.user import UserService
from core.stats import Stats

def main(*, devmode: bool = False) -> None:
	sys.excepthook = _excepthook
	
	import asyncio
	from core.backend import Backend
	from core import http
	import settings
	
	loop = asyncio.get_event_loop()
	
	user_service = UserService(Conn(settings.DB))
	auth_service = AuthService()
	login_auth_service = LoginAuthService(Conn(settings.DB))
	stats_service = Stats(Conn(settings.STATS_DB))
	backend = Backend(loop, user_service = user_service, login_auth_service = login_auth_service, auth_service = auth_service, stats_service = stats_service)
	http_app = http.register(loop, backend, devmode = devmode)
	
	if settings.ENABLE_FRONT_MSN:
		import front.msn
		front.msn.register(loop, backend, http_app)
	if settings.ENABLE_FRONT_YMSG:
		import front.ymsg
		front.ymsg.register(loop, backend, http_app, devmode = devmode)
	if settings.ENABLE_FRONT_IRC:
		import front.irc
		front.irc.register(loop, backend, devmode = devmode)
	if settings.ENABLE_FRONT_API:
		import front.api
		front.api.register(http_app)
	if settings.ENABLE_FRONT_BOT:
		import front.bot
		front.bot.register(loop, backend)
	if settings.ENABLE_S2S:
		import core.site2server
		core.site2server.register(loop, backend)
	
	import core.sysboard
	core.sysboard.register(loop, backend, devmode = devmode)
	
	if devmode:
		if settings.ENABLE_FRONT_DEVBOTS:
			import front.devbots
			front.devbots.register(loop, backend)
		
		import dev.webconsole
		dev.webconsole.register(loop, backend, http_app)
	
	backend.run_forever()

def _excepthook(type_: Type[BaseException], value: BaseException, traceback: TracebackType) -> None:
	# TODO: Something useful
	sys.__excepthook__(type_, value, traceback)

if __name__ == '__main__':
	main()
