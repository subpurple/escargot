from typing import Optional, Callable
import asyncio

from aiohttp import web

from core.backend import Backend
from util.misc import Logger
import settings

from .msnp import MSNPCtrl

def register(loop: asyncio.AbstractEventLoop, backend: Backend, http_app: web.Application) -> None:
	from util.misc import ProtocolRunner
	from . import msnp_ns, msnp_sb
	from .http import abservice, gateway, other
	
	backend.add_runner(ProtocolRunner('0.0.0.0', 1863, ListenerMSNP, args = ['NS', backend, msnp_ns.MSNPCtrlNS]))
	backend.add_runner(ProtocolRunner('0.0.0.0', 1864, ListenerMSNP, args = ['SB', backend, msnp_sb.MSNPCtrlSB]))
	other.register(http_app)
	abservice.register(http_app)
	gateway.register(loop, http_app)

class ListenerMSNP(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: MSNPCtrl
	transport: Optional[asyncio.WriteTransport]
	
	def __init__(self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], MSNPCtrl]) -> None:
		super().__init__()
		self.logger = Logger(logger_prefix, self, settings.DEBUG_MSNP)
		self.backend = backend
		self.controller = controller_factory(self.logger, 'direct', backend)
		self.controller.close_callback = self._on_close
		self.transport = None
	
	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.WriteTransport)
		self.transport = transport
		self.logger.log_connect()
		self.controller.on_connect()
	
	def connection_lost(self, exc: Optional[Exception]) -> None:
		self.controller.close()
		self.logger.log_disconnect()
		self.transport = None
	
	def data_received(self, data: bytes) -> None:
		transport = self.transport
		assert transport is not None
		# Setting `transport` to None so all data is held until the flush
		#self.controller.transport = None
		if self.controller.transport is None:
			self.controller.transport = self.transport
		self.controller.data_received(data)
		#transport.write(self.controller.flush())
		#self.controller.transport = transport
	
	def _on_close(self) -> None:
		if self.transport is None: return
		self.transport.close()
