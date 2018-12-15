import argparse
from util import misc, hash
from core.db import Session, User, ABStore, ABMetadata
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from core.models import NetworkID
from datetime import datetime
import base64

from front.msn.misc import cid_format

def main() -> None:
	parser = argparse.ArgumentParser(description = "Create user/change password.")
	parser.add_argument('email', help = "email of new/existing user")
	parser.add_argument('password')
	parser.add_argument(
		'--old-msn', dest = 'support_old_msn', action = 'store_const',
		const = True, default = False, help = "old MSN support"
	)
	parser.add_argument(
		'--yahoo', dest = 'support_yahoo', action = 'store_const',
		const = True, default = False, help = "Yahoo! support"
	)
	parser.add_argument(
		'--irc', dest = 'support_irc', action = 'store_const',
		const = True, default = False, help = "IRC support"
	)
	args = parser.parse_args()
	
	email = args.email
	pw = args.password
	new_user = False
	
	if args.support_yahoo:
		networkid = NetworkID.YAHOO
	elif args.support_irc:
		networkid = NetworkID.IRC
	else:
		networkid = NetworkID.WINDOWS_LIVE
	
	with Session() as sess:
		user = sess.query(User).filter(User.email == email, User.networkid == int(networkid)).one_or_none()
		if user is None:
			print("Creating new user...")
			user = User(
				uuid = misc.gen_uuid(), networkid = int(networkid), email = email, verified = False,
				name = email, message = '',
				settings = {}, groups = {}, contacts = {},
			)
			if networkid is not NetworkID.IRC:
				user.subscribed_ab_stores = ['00000000-0000-0000-0000-000000000000']
				abmetadata = sess.query(ABMetadata).filter(ABMetadata.ab_id == '00000000-0000-0000-0000-000000000000').one_or_none()
				if not abmetadata:
					abmetadata = ABMetadata(
						ab_id = '00000000-0000-0000-0000-000000000000', ab_type = 'Individual',
					)
					sess.add(abmetadata)
				
				abstore = ABStore(
					member_uuid = user.uuid, ab_id = '00000000-0000-0000-0000-000000000000',
				)
				abstore.date_last_modified = datetime.utcnow()
				sess.add(abstore)
			if networkid is NetworkID.WINDOWS_LIVE:
				ticketxml = '<?xml version="1.0" encoding="utf-16"?>\r\n<Ticket xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">\r\n  <TS>{}</TS>\r\n  <CID>{}</CID>\r\n</Ticket>'.format(
					datetime.utcnow().isoformat()[0:19] + 'Z', cid_format(user.uuid, decimal = True)
				).encode('utf-8')
				user.set_front_data('msn', 'circleticket', [base64.b64encode(ticketxml).decode('ascii'), base64.b64encode(pkcs1_15.new(RSA.generate(2048)).sign(SHA1.new(ticketxml))).decode('ascii')])
		else:
			print("User exists, changing password...")
		set_passwords(user, pw, support_old_msn = args.support_old_msn, support_yahoo = args.support_yahoo)
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
	main()
