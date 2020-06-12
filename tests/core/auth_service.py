import pytest

from core.auth import AuthService

def test_can_use_existing(time_service, auth_service):
	t = time_service
	a = auth_service
	token, _ = a.create_token('xyz', 'data', lifetime = 10)
	t.tick(5)
	assert a.pop_token('xyz', token) == 'data'
	assert a.pop_token('xyz', token) is None

def test_cant_use_expired(time_service, auth_service):
	t = time_service
	a = auth_service
	token, _ = a.create_token('xyz', 'data', lifetime = 10)
	t.tick(11)
	assert a.pop_token('xyz', token) is None

def test_cant_use_wrong_purpose(time_service, auth_service):
	t = time_service
	a = auth_service
	token, _ = a.create_token('xyz', 'data', lifetime = 10)
	assert a.pop_token('zyx', token) is None
	assert a.pop_token('xyz', token) is None

def test_multiple_in_order(time_service, auth_service):
	t = time_service
	a = auth_service
	token1, _ = a.create_token('xyz', 'data1', lifetime = 10)
	t.tick(5)
	token2, _ = a.create_token('abc', 'data2', lifetime = 15)
	t.tick(3)
	assert a.pop_token('xyz', token1) == 'data1'
	t.tick(10)
	assert a.pop_token('abc', token2) == 'data2'

def test_multiple_out_of_order(time_service, auth_service):
	t = time_service
	a = auth_service
	token1, _ = a.create_token('xyz', 'data1', lifetime = 10)
	t.tick(5)
	token2, _ = a.create_token('abc', 'data2', lifetime = 15)
	t.tick(3)
	assert a.pop_token('abc', token2) == 'data2'
	t.tick(1)
	assert a.pop_token('xyz', token1) == 'data1'

@pytest.fixture
def auth_service(time_service: 'MockTime') -> 'AuthService':
	return AuthService(time = time_service)

@pytest.fixture
def time_service() -> 'MockTime':
	return MockTime()

class MockTime:
	t: float
	
	def __init__(self) -> None:
		self.t = 0
	
	def tick(self, dt: float = 1) -> None:
		self.t += dt
	
	def __call__(self) -> float:
		return self.t
