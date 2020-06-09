from typing import Optional, Callable

import asyncio, settings

from core.backend import Backend
from util.misc import Logger

from .ctrl import IRCCtrl

def register(loop: asyncio.AbstractEventLoop, backend: Backend, *, devmode: bool = False) -> None:
	from util.misc import ProtocolRunner
	backend.add_runner(ProtocolRunner('0.0.0.0', 6667, ListenerIRC, args = ['IR', backend, IRCCtrl]))
	if settings.ENABLE_FRONT_IRC_SSL:
		if devmode:
			from devtls import DevTLS
			ssl_context = DevTLS('Escargot').create_ssl_context()
		else:
			from core.tls import TLSContext
			ssl_context = TLSContext(settings.CERT_ROOT, settings.CERT_DIR).create_ssl_context()
		backend.add_runner(ProtocolRunner('0.0.0.0', 6697, ListenerIRC, args = ['IR', backend, IRCCtrl], ssl_context = ssl_context))

class ListenerIRC(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: IRCCtrl
	transport: Optional[asyncio.WriteTransport]
	
	def __init__(self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], IRCCtrl]) -> None:
		super().__init__()
		self.logger = Logger(logger_prefix, self, settings.DEBUG_IRC)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None
	
	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.WriteTransport)
		self.transport = transport
		self.logger.log_connect()
	
	def connection_lost(self, exc: Optional[Exception]) -> None:
		self.controller.close()
		self.logger.log_disconnect()
		self.transport = None
	
	def data_received(self, data: bytes) -> None:
		transport = self.transport
		assert transport is not None
		if self.backend.maintenance_mode:
			transport.close()
			return
		#self.controller.transport = None
		if self.controller.transport is None:
			self.controller.transport = self.transport
		self.controller.data_received(data)
		#transport.write(self.controller.flush())
		#self.controller.transport = transport
	
	def _on_close(self) -> None:
		if self.transport is None: return
		self.transport.close()
