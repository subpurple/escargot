import getpass
from datetime import datetime

from util import misc, hash
from core.db import Session, User, ABStore, ABMetadata

def main(email: str, *, oldmsn: bool = False, yahoo: bool = False) -> None:
	with Session() as sess:
		user = sess.query(User).filter(User.email == email).one_or_none()
		if user is None:
			print("Creating new user...")
			user = User(
				uuid = misc.gen_uuid(), email = email, verified = False,
				name = email, message = '',
				settings = {},
			)
			
			user.subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000']
			abmetadata = sess.query(ABMetadata).filter(ABMetadata.ab_id == '00000000-0000-0000-0000-000000000000').one_or_none()
			if not abmetadata:
				abmetadata = ABMetadata(
					ab_id = '00000000-0000-0000-0000-000000000000', ab_type = 'Individual',
				)
				sess.add(abmetadata)
			
			now = datetime.utcnow()
			
			abstore = ABStore(
				member_uuid = user.uuid, ab_id = '00000000-0000-0000-0000-000000000000',
			)
			abstore.date_last_modified = now
			sess.add(abstore)
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
