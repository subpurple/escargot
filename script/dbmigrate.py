from typing import Optional
from sqlaltery import SQLAltery

from core import db
from core.conn import Conn
import settings

def diff() -> None:
	salt = _get_salt()
	for op in salt._diff(db.Base.metadata):
		print(op)

def generate() -> None:
	salt = _get_salt()
	salt.generate(db.Base.metadata)

def migrate(*, revision: Optional[int] = None, fake: bool = False) -> None:
	salt = _get_salt()
	conn_db = Conn(settings.DB)
	with conn_db.engine.connect() as conn:
		salt.migrate(conn, revision, fake = fake)

def _get_salt() -> SQLAltery:
	return SQLAltery('migrations')

if __name__ == '__main__':
	import funcli
	funcli.main({ generate, migrate, diff })
