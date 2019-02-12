from sqlaltery import SQLAltery
from core import db, stats

def main():
	create_dbs()

def create_dbs():
	db.Base.metadata.create_all(db.engine)
	with db.engine.connect() as conn:
		SQLAltery('migrations').migrate(conn, fake = True)
	stats.Base.metadata.create_all(stats.engine)

if __name__ == '__main__':
	main()
