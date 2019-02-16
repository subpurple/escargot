from typing import Optional
import asyncio

from core.backend import Backend

def register(backend: Backend) -> None:
	from util.misc import ProtocolRunner
	
	backend.add_runner(ProtocolRunner('0.0.0.0', 5100, ListenerVideoChat))

class ListenerVideoChat(asyncio.Protocol):
	def connection_made(self, transport: asyncio.BaseTransport) -> None:
		print("Video chat connection_made")
	
	def connection_lost(self, exc: Optional[Exception]) -> None:
		print("Video chat connection_lost")
	
	def data_received(self, data: bytes) -> None:
		print("Video chat data_received", data)
