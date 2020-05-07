from typing import Set, Iterator, Any
from core import db
from core.conn import Conn
import settings

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
	
	conn = Conn(settings.DB)
	with conn.session() as sess:
		users = sess.query(db.User).filter(db.User.email.in_(emails))
		ids = { u.id for u in users }
		print("delete account", len(ids))
		usercontacts = sess.query(db.UserContact).filter(db.UserContact.user_id.in_(ids))
		if usercontacts:
			usercontacts.delete(synchronize_session = False)
		users.delete(synchronize_session = False)
		for u in sess.query(db.User).all():
			if _remove_from_contacts(sess, u, ids):
				sess.add(u)
		for gc in sess.query(db.GroupChat).all():
			_remove_from_groupchat(sess, gc, ids)
		sess.flush()

def _remove_from_contacts(sess: Any, user: db.User, ids: Set[str]) -> bool:
	none_found = True
	usercontacts = sess.query(db.UserContact).filter(db.UserContact.user_id == user.id, db.UserContact.contact_id.in_(ids))
	if not usercontacts: return False
	usercontacts.delete(synchronize_session = False)
	print("contacts", user.email)
	return True

def _remove_from_groupchat(sess: Any, groupchat: db.GroupChat, ids: Set[str]) -> None:
	chat_id = groupchat.chat_id
	memberships = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id == chat_id, db.GroupChatMembership.member_id.in_(ids))
	if not memberships: return
	memberships.delete(synchronize_session = False)
	if groupchat.owner_id in ids:
		sess.delete(groupchat)
	print("groupchat", chat_id)

if __name__ == '__main__':
	import funcli
	funcli.main()
