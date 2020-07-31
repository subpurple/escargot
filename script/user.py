import getpass
from datetime import datetime

from util import misc, hash
from core.db import User
from core.conn import Conn
import settings

def main(email: str, username: str, *, oldmsn: bool = False, yahoo: bool = False) -> None:
	conn = Conn(settings.DB)
	with conn.session() as sess:
		user = sess.query(User).filter(User.email == email).one_or_none()
		if user is None:
			user = sess.query(User).filter(User.username == username).one_or_none()
			if user is not None:
				print('User does not exist, but username is already taken. Exiting.')
				return
			
			print("Creating new user...")
			user = User(
				uuid = misc.gen_uuid(), email = email, username = username, verified = False,
				friendly_name = email,
				groups = {}, settings = {},
			)
		else:
			print("User exists, changing password...")
		pw = getpass.getpass("Password: ")
		set_passwords(user, pw, support_old_msn = oldmsn, support_yahoo = yahoo)
		sess.add(user)
	
	print("Done.")

def set_passwords(user: User, pw: str, *, support_old_msn: bool = False, support_yahoo: bool = False) -> None:
	user.password = hash.hasher.encode(pw)
	
	if support_old_msn:
		pw_md5 = hash.hasher_md5.encode(pw)
		user.set_front_data('msn', 'pw_md5', pw_md5)
	
	if support_yahoo:
		pw_md5_unsalted = hash.hasher_md5.encode(pw, salt = '')
		user.set_front_data('ymsg', 'pw_md5_unsalted', pw_md5_unsalted)
		
		pw_md5crypt = hash.hasher_md5crypt.encode(pw, salt = '$1$_2S43d5f')
		user.set_front_data('ymsg', 'pw_md5crypt', pw_md5crypt)

if __name__ == '__main__':
	import funcli
	funcli.main()
