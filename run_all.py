from typing import Any, Type
from types import TracebackType
import sys

def main(*, devmode: bool = False) -> None:
	sys.excepthook = _excepthook
	
	import asyncio
	from core.backend import Backend
	from core import http
	import settings
	
	loop = asyncio.get_event_loop()
	backend = Backend(loop)
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
	sys.__excepthook__(type, value, traceback)

if __name__ == '__main__':
	main()
