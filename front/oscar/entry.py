import asyncio
import struct
import settings

from core.backend import Backend
from .ctrl import OSCARCtrl
from typing import Optional, Callable
from threading import Thread
from util.misc import Logger, ProtocolRunner
from .misc import SNACMessage


def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
    backend.add_runner(ProtocolRunner('0.0.0.0', 5190, ListenerOSCAR, args=['OS', OSCARCtrl]))


class ListenerOSCAR(asyncio.Protocol):
    logger: Logger
    controller: OSCARCtrl
    transport: Optional[asyncio.WriteTransport]

    buffer: bytes = b''
    data_thread: Thread = None

    def __init__(self, logger_prefix: str, controller_factory: Callable[[Logger, str], OSCARCtrl]) -> None:
        super().__init__()

        self.logger = Logger(logger_prefix, self, settings.DEBUG_OSCAR)
        self.controller = controller_factory(self.logger)
        self.controller.close_callback = self._on_close

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.controller.transport = transport
        self.controller.on_connect()
        self.logger.log_connect()

    def connection_lost(self, exc: Optional[Exception]) -> None:
        # self.controller.close()
        self.logger.log_disconnect()

    def data_received(self, packet: bytes) -> None:
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
                data = self.buffer[6:length + 6]

                match frame:
                    # SIGNON
                    case 0x01:
                        self.controller.on_signon_frame(data)

                    # DATA (always contains a SNAC)
                    case 0x02:
                        if len(data) < 10:
                            return

                        msg = SNACMessage()
                        msg.unmarshal(data)
                        self.controller.on_data_frame(msg)

                    # ERROR
                    case 0x03:
                        self.controller.on_error_frame(data)

                    # SIGNOFF
                    case 0x04:
                        self.controller.on_signoff_frame(data)

                    # KEEP_ALIVE
                    case 0x05:
                        pass

                    case _:
                        self.logger.info('Recieved unknown frame:', str(frame), 'with data:', data.hex())

                self.buffer = self.buffer[length + 6:]

            if len(self.buffer) < 6:
                break

    def _on_close(self) -> None:
        if self.transport is not None:
            self.transport.close()
