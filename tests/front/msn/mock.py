from collections import deque
from typing import Deque, Any, Iterable, Tuple

from front.msn.misc import MSNObj

class Logger:
	def __init__(self, prefix: str, obj: object, front_debug: bool) -> None:
		pass
	
	def info(self, *args: Any) -> None:
		pass
	
	def error(self, exc: Exception) -> None:
		pass
	
	def log_connect(self) -> None:
		pass
	
	def log_disconnect(self) -> None:
		pass

DecodedMSNP = Tuple[Any, ...]

class MSNPWriter:
	__slots__ = ('_q',)
	
	_q: Deque[DecodedMSNP]
	
	def __init__(self) -> None:
		self._q = deque()
	
	def write(self, m: Iterable[Any]) -> None:
		self._q.append(tuple(str(x) for x in m if (not isinstance(x, MSNObj) and x is not None) or (isinstance(x, MSNObj) and x.data is not None)))
	
	def pop_message(self, *msg_expected: Any) -> DecodedMSNP:
		msg = self._q.popleft()
		assert len(msg) == len(msg_expected)
		for mi, mei in zip(msg, msg_expected):
			if mei is ANY: continue
			assert mi == str(mei)
		return msg
	
	def assert_empty(self) -> None:
		assert not self._q

class AnyCls:
	def __repr__(self) -> str: return '<ANY>'
ANY = AnyCls()
