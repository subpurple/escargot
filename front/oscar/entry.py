import asyncio
import struct
import settings

from typing import Optional, Callable
from util.misc import Logger
from core.backend import Backend
from .ctrl import OSCARCtrl
from threading import Thread

def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	from util.misc import ProtocolRunner
	
	backend.add_runner(ProtocolRunner('0.0.0.0', 5190, ListenerOSCAR, args = ['OS', backend, OSCARCtrl]))


class ListenerOSCAR(asyncio.Protocol):
	logger: Logger
	backend: Backend
	controller: OSCARCtrl
	transport: Optional[asyncio.WriteTransport]

	buffer: bytes = b''
	data_thread: Thread = None

	def __init__(self, logger_prefix: str, backend: Backend, controller_factory: Callable[[Logger, str, Backend], OSCARCtrl]) -> None:
		super().__init__()

		self.logger = Logger(logger_prefix, self, settings.DEBUG_OSCAR)
		self.backend = backend
		self.controller = controller_factory(self.logger, backend)
		self.controller.close_callback = self._on_close

	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		assert isinstance(transport, asyncio.WriteTransport)

		self.controller.transport = transport
		self.logger.log_connect()
		self.controller.on_connect()
	
	def connection_lost(self, exc: Optional[Exception]) -> None:
		self.controller.close()
		self.logger.log_disconnect()
	
	def data_received(self, packet: bytes) -> None:
		if self.backend.maintenance_mode:	
			self.transport.close()
			return

		self.buffer += packet

		if self.data_thread is None or not self.data_thread.is_alive():
			self.data_thread = Thread(target=self.parse_buffer)
			self.data_thread.start()

	def parse_buffer(self) -> None:
		while True:
			if self.buffer[0] != 0x2A:
				break

			frame, sequence, length = struct.unpack('>BHH', self.buffer[1:6])

			if len(self.buffer) < length + 6:
				break
			
			if len(self.buffer) >= length + 6:
				self.controller.data_received(frame, sequence, self.buffer[6:length + 6])
				self.buffer = self.buffer[length + 6:]

			# TODO(subpurple): This check might not be needed due to the "if len(self.buffer) < length + 6:" check above
			if len(self.buffer) < 6:
				break

	def _on_close(self) -> None:
		if self.transport is None: 
			return
		self.transport.close()
