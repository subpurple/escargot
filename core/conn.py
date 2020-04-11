from typing import Any, Iterator
from contextlib import contextmanager
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

class Conn:
	__slots__ = ('engine', 'session_factory', '_session', '_depth')
	
	engine: Any
	session_factory: Any
	_session: Any
	_depth: int
	
	def __init__(self, conn_str: str) -> None:
		self.engine = sa.create_engine(conn_str)
		self.session_factory = sessionmaker(bind = self.engine)
		self._session = None
		self._depth = 0
	
	@contextmanager
	def session(self) -> Iterator[Any]:
		if self._depth > 0:
			yield self._session
			return
		sess = self.session_factory()
		self._session = sess
		self._depth += 1
		try:
			yield sess
			sess.commit()
		except:
			sess.rollback()
			raise
		finally:
			sess.close()
			self._session = None
			self._depth -= 1
