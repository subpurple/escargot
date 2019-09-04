from typing import Set
from core import db

def main(*emails: str) -> None:
	if not emails:
		print("Nothing to do.")
		return
	print("Deleting {} accounts:".format(len(emails)))
	for e in emails:
		print('=>', e)
	ans = input("Are you sure? (y/N) ")
	if ans.lower() != 'y':
		print("Operation cancelled.")
		return
	print("Deleting.")
	
	with db.Session() as sess:
		users = sess.query(db.User).filter(db.User.email.in_(emails))
		ids = { u.id for u in users }
		print("delete account", len(uuids))
		users.delete(synchronize_session = False)
		for u in sess.query(db.User).all():
			if _remove_from_contacts(u, ids):
				sess.add(u)
		sess.flush()

def _remove_from_contacts(user: db.User, ids: Set[str]) -> bool:
	none_found = True
	usercontacts = sess.query(db.UserContact).filter(db.UserContact.user_id.in_(ids))
	if not usercontacts: return False
	usercontacts.delete(synchronize_session = False)
	print("contacts", user.email)
	return True

if __name__ == '__main__':
	import funcli
	funcli.main()
