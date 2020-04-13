from typing import FrozenSet, Any, Iterable, Optional, TypeVar, List, Dict, Tuple, Generic, TYPE_CHECKING
from abc import ABCMeta, abstractmethod
import asyncio
import functools
import itertools
import traceback
from datetime import datetime
from uuid import uuid4
import ssl
import jinja2
from aiohttp import web

EMPTY_SET: FrozenSet[Any] = frozenset()

if TYPE_CHECKING:
	VoidTaskType = asyncio.Task[None]
else:
	VoidTaskType = Any

def gen_uuid() -> str:
	return str(uuid4())

T = TypeVar('T')
def first_in_iterable(iterable: Iterable[T]) -> Optional[T]:
	for x in iterable: return x
	return None

def last_in_iterable(iterable: Iterable[T]) -> Optional[T]:
	last = None
	
	for x in iterable:
		last = x
	return last

class Runner(metaclass = ABCMeta):
	__slots__ = ('host', 'port', 'ssl_context', 'ssl_only')
	
	host: str
	port: int
	ssl_context: Optional[ssl.SSLContext]
	ssl_only: bool
	
	def __init__(self, host: str, port: int, *, ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False) -> None:
		self.host = host
		self.port = port
		self.ssl_context = ssl_context
		self.ssl_only = ssl_only
	
	@abstractmethod
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]: pass
	
	def teardown(self, loop: asyncio.AbstractEventLoop) -> Any:
		pass

class ProtocolRunner(Runner):
	__slots__ = ('_protocol')
	
	_protocol: Any
	
	def __init__(
		self, host: str, port: int, protocol: Any, *, args: Optional[List[Any]] = None,
		ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False,
	) -> None:
		super().__init__(host, port, ssl_context = ssl_context, ssl_only = ssl_only)
		if args:
			protocol = functools.partial(protocol, *args)
		self._protocol = protocol
	
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]:
		return [loop.create_server(self._protocol, self.host, self.port, ssl = self.ssl_context)]

class AIOHTTPRunner(Runner):
	__slots__ = ('app', '_handler')
	
	app: Any
	_handler: Optional[Any]
	
	def __init__(self, host: str, port: int, app: Any, *, ssl_context: Optional[ssl.SSLContext] = None, ssl_only: bool = False) -> None:
		super().__init__(host, port, ssl_context = ssl_context, ssl_only = ssl_only)
		self.app = app
		self._handler = None
	
	def create_servers(self, loop: asyncio.AbstractEventLoop) -> List[Any]:
		assert self._handler is None
		self._handler = self.app.make_handler(loop = loop)
		loop.run_until_complete(self.app.startup())
		
		ret = []
		if not self.ssl_only:
			ret.append(loop.create_server(self._handler, self.host, self.port, ssl = None))
		if self.ssl_context is not None:
			ret.append(loop.create_server(self._handler, self.host, (self.port if self.ssl_only else 443), ssl = self.ssl_context))
		return ret
	
	def teardown(self, loop: asyncio.AbstractEventLoop) -> None:
		handler = self._handler
		assert handler is not None
		self._handler = None
		loop.run_until_complete(self.app.shutdown())
		loop.run_until_complete(handler.shutdown(60))
		loop.run_until_complete(self.app.cleanup())

class Logger:
	__slots__ = ('prefix', '_log')
	
	prefix: str
	_log: bool
	
	def __init__(self, prefix: str, obj: object, front_debug: bool) -> None:
		import settings
		self.prefix = '{}/{:04x}'.format(prefix, hash(obj) % 0xFFFF)
		self._log = settings.DEBUG and front_debug
	
	def info(self, *args: Any) -> None:
		if self._log:
			print(self.prefix, *args)
	
	def error(self, exc: Exception) -> None:
		traceback.print_exception(type(exc), exc, exc.__traceback__)
	
	def log_connect(self) -> None:
		self.info("con")
	
	def log_disconnect(self) -> None:
		self.info("dis")

def run_loop(loop: asyncio.AbstractEventLoop, runners: List[Runner]) -> None:
	for runner in runners:
		print("Serving on {}:{}".format(runner.host, runner.port))
	
	task = loop.create_task(_windows_ctrl_c_workaround())
	
	foos = itertools.chain(*(
		runner.create_servers(loop) for runner in runners
	))
	servers = loop.run_until_complete(asyncio.gather(*foos))
	
	try:
		loop.run_forever()
	except KeyboardInterrupt:
		# To prevent "Task exception was never retrieved"
		if task.done():
			task.exception()
		raise
	finally:
		for server in servers:
			server.close()
		loop.run_until_complete(asyncio.gather(*(
			server.wait_closed() for server in servers
		)))
		for runner in runners:
			runner.teardown(loop)
		server_temp_cleanup()
		loop.close()

async def _windows_ctrl_c_workaround() -> None:
	import os
	if os.name != 'nt': return
	
	# https://bugs.python.org/issue23057
	while True:
		await asyncio.sleep(0.1)

def add_to_jinja_env(app: web.Application, prefix: str, tmpl_dir: str, *, globals: Optional[Dict[str, Any]] = None) -> None:
	jinja_env = app['jinja_env']
	jinja_env.loader.mapping[prefix] = jinja2.FileSystemLoader(tmpl_dir)
	if globals:
		jinja_env.globals.update(globals)

def arbitrary_decode(d: bytes) -> str:
	if not d: return ''
	
	return ''.join(map(chr, [b for b in d]))

def arbitrary_encode(s: str) -> bytes:
	return bytes([ord(c) for c in s])

def date_format(d: Optional[datetime]) -> Optional[str]:
	if d is None:
		return None
	d_iso = '{}{}'.format(
		d.isoformat()[0:19], 'Z',
	)
	return d_iso

def server_temp_cleanup() -> None:
	# For now, just clean up stuff in the Yahoo! HTTP file transfer storage folder
	
	import shutil
	from pathlib import Path
	
	path = Path('storage/file')
	if not path.exists():
		return
	for file_dir in path.iterdir():
		shutil.rmtree(str(file_dir), ignore_errors = True)

K = TypeVar('K')
V = TypeVar('V')
class DefaultDict(Dict[K, V]):
	_default: V
	
	def __init__(self, default: V, mapping: Dict[K, V]) -> None:
		super().__init__(mapping)
		self._default = default
	
	def __getitem__(self, key: K) -> V:
		v = super().__getitem__(key)
		if v is None:
			v = self._default
		return v

class MultiDict(Generic[K, V]):
	_impl: List[Tuple[K, V]]
	
	def __init__(self, data: Optional[Iterable[Tuple[K, V]]] = None) -> None:
		super().__init__()
		self._impl = ([] if data is None else list(data))
	
	def __contains__(self, key: K) -> bool:
		for d in self._impl:
			if d[0] == key: return True
		return False
	
	def add(self, key: K, value: V) -> None:
		self._impl.append((key, value))
	
	def get(self, key: K) -> Optional[V]:
		for d in self._impl:
			if d[0] == key: return d[1]
		return None
	
	def getall(self, key: K) -> Optional[Iterable[V]]:
		values = [] # type: List[V]
		for d in self._impl:
			if d[0] == key:
				values.append(d[1])
		return values if values else None
	
	def items(self) -> Iterable[Tuple[K, V]]:
		return self._impl
