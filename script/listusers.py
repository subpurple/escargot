from typing import Optional
from datetime import datetime, timedelta
from core import db
from core.conn import Conn
import settings

def main(*, since: int = 60, verbose: bool = False) -> None:
	online_since = datetime.utcnow() - timedelta(minutes = since)
	total = 0
	total_online = 0
	
	conn = Conn(settings.DB)
	with conn.session() as sess:
		for u in sess.query(db.User).all():
			total += 1
			if verbose:
				print(u.email)
			if online_since is not None and u.date_login is not None:
				total_online += (1 if u.date_login >= online_since else 0)
	
	print("Total:", total)
	if online_since is not None:
		print("Online:", total_online)

if __name__ == '__main__':
	import funcli
	funcli.main()
