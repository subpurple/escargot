import getpass
from db import Session, User
from util.misc import gen_uuid
from util import hash

def main(email: str, *, old: bool = False) -> None:
	with Session() as sess:
		user = sess.query(User).filter(User.email == email).one_or_none()
		if user is None:
			print("Creating new user...")
			user = User(
				uuid = gen_uuid(), email = email, verified = False,
				name = email, message = '',
				settings = {}, groups = {}, contacts = {},
			)
		else:
			print("User exists, changing password...")
		pw = getpass.getpass("Password: ")
		_set_passwords(user, pw, old)
		sess.add(user)
	
	print("Done.")

def _set_passwords(user, pw, support_old):
	user.password = hash.hasher.encode(pw)
	user.password_md5 = (hash.hasher_md5.encode(pw) if support_old else '')

if __name__ == '__main__':
	import funcli
	funcli.main()
