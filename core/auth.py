from typing import Dict, List, Tuple, Any, Optional
import bisect
from time import time as time_builtin
from datetime import datetime, timedelta
from functools import total_ordering
from util.hash import gen_salt

from .db import LoginToken
from .conn import Conn

def GenTokenStr(trim: int = 20) -> str:
	return gen_salt(trim)

class LoginAuthService:
	__slots__ = ('_conn',)
	
	_conn: Conn
	
	def __init__(self, conn: Conn) -> None:
		self._conn = conn
	
	def create_token(self, purpose: str, data: List[Any], *, token: Optional[str] = None, lifetime: int = 30) -> Tuple[str, datetime]:
		with self._conn.session() as sess:
			logintoken = sess.query(LoginToken).filter(LoginToken.token == token, LoginToken.purpose == purpose).one_or_none()
			assert logintoken is None
			logintoken = LoginToken(
				token = (GenTokenStr() if token is None else token), purpose = purpose,
				data = data, expiry = datetime.utcnow() + timedelta(seconds = lifetime),
			)
			sess.add(logintoken)
			
			return logintoken.token, logintoken.expiry
	
	def get_token(self, purpose: str, token: str) -> Optional[List[Any]]:
		with self._conn.session() as sess:
			logintoken = sess.query(LoginToken).filter(LoginToken.token == token, LoginToken.purpose == purpose).one_or_none()
			if logintoken is None: return None
			if logintoken.expiry <= datetime.utcnow(): return None
			return logintoken.data
	
	def remove_expired(self) -> None:
		with self._conn.session() as sess:
			sess.query(LoginToken).filter(LoginToken.expiry <= datetime.utcnow()).delete()

class AuthService:
	__slots__ = ('_time', '_ordered', '_bytoken', '_idxbase')
	
	_time: Any
	# Ordered by TokenData.expiry
	_ordered: List['TokenData']
	_bytoken: Dict[str, int]
	_idxbase: int
	
	def __init__(self, *, time: Optional[Any] = None) -> None:
		if time is None:
			time = time_builtin
		self._time = time
		self._ordered = []
		self._bytoken = {}
		self._idxbase = 0
	
	def create_token(self, purpose: str, data: Any, *, token: Optional[str] = None, lifetime: int = 30) -> Tuple[str, int]:
		self._remove_expired()
		td = TokenData(purpose, data, self._time() + lifetime, token = GenTokenStr() if token is None else token)
		assert td.token not in self._bytoken
		idx = bisect.bisect_left(self._ordered, td)
		self._ordered.insert(idx, td)
		self._bytoken[td.token] = idx + self._idxbase
		return td.token, td.expiry
	
	def pop_token(self, purpose: str, token: str) -> Optional[Any]:
		self._remove_expired()
		idx = self._bytoken.pop(token, None)
		if idx is None: return None
		idx -= self._idxbase
		td = self._ordered[idx]
		if not td.validate(purpose, token, self._time()): return None
		return td.data
	
	def get_token(self, purpose: str, token: str) -> Optional[Any]:
		self._remove_expired()
		idx = self._bytoken.get(token)
		if idx is None: return None
		idx -= self._idxbase
		td = self._ordered[idx]
		if not td.validate(purpose, token, self._time()): return None
		return td.data
	
	def get_token_expiry(self, purpose: str, token: str) -> Optional[Any]:
		self._remove_expired()
		idx = self._bytoken.get(token)
		if idx is None: return None
		idx -= self._idxbase
		td = self._ordered[idx]
		if not td.validate(purpose, token, self._time()): return None
		return td.expiry
	
	def _remove_expired(self) -> None:
		if not self._ordered: return
		dummy = TokenData('', None, self._time(), '')
		idx = bisect.bisect(self._ordered, dummy)
		if idx < 1: return
		self._idxbase += idx
		for td in self._ordered[:idx]:
			self._bytoken.pop(td.token, None)
		self._ordered = self._ordered[idx:]

@total_ordering
class TokenData:
	__slots__ = ('token', 'purpose', 'data', 'expiry')
	
	token: str
	purpose: str
	data: Any
	expiry: int
	
	def __init__(self, purpose: str, data: Any, expiry: int, token: str) -> None:
		self.token = token
		self.purpose = purpose
		self.expiry = expiry
		self.data = data
	
	def __le__(self, other: 'TokenData') -> bool:
		return self.expiry <= other.expiry
	
	def validate(self, purpose: str, token: str, now: int) -> bool:
		if self.expiry <= now: return False
		if self.purpose != purpose: return False
		if self.token != token: return False
		return True
