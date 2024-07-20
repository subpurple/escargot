import asyncio
import struct
import random

from typing import Optional, Any
from util.misc import Logger
from core.backend import Backend

class OSCARCtrl:
    logger: Logger
    transport: Optional[asyncio.WriteTransport]
    backend: Backend
    closed: bool

    sequence: int = random.randint(0x0000, 0xFFFF)
	
    def __init__(self, logger: Logger, backend: Backend) -> None:
        self.logger = logger
        self.transport = None
        self.backend = backend
    
    def on_connect(self) -> None:
        self.send_reply(0x01, bytearray.fromhex('00 00 00 01'.replace(' ', '')))
    
    def data_received(self, frame: int, sequence: int, data: bytes) -> None:
        self.logger.info('Frame:', frame)
        self.logger.info('Sequence:', sequence)
        self.logger.info('Data:', data.hex())

    def send_reply(self, frame: int, data: bytes) -> None:
        if self.sequence == 0xFFFF:
            self.sequence = 0x0000
        else:
            self.sequence += 1
        
        packet = struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)) + data
        self.logger.info('Sending:', packet.hex())
        self.transport.write(packet)

    def close(self, **kwargs: Any) -> None:
        pass
