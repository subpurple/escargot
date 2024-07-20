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

    sequence: int
	
    def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
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
        if sequence == 0xFFFF:
            sequence = 0x0000
        else:
            sequence += 1
        
        self.transport.write(struct.pack('>BBHH', 0x2A, frame, sequence, data))

    def close(self, **kwargs: Any) -> None:
        pass
