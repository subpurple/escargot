from typing import Set
from core import db
from core.conn import Conn
import settings

def main(*ids: str) -> None:
	if not ids:
		print("Nothing to do.")
		return
	print("Deleting {} group chats:".format(len(ids)))
	for i in ids:
		print('=>', i)
	ans = input("Are you sure? (y/N) ")
	if ans.lower() != 'y':
		print("Operation cancelled.")
		return
	print("Deleting.")
	
	conn = Conn(settings.DB)
	with conn.session() as sess:
		groupchats = sess.query(db.GroupChat).filter(db.GroupChat.chat_id.in_(ids))
		groupchatmemberships = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id.in_(ids))
		print("delete group chats", len(ids))
		groupchatmemberships.delete(synchronize_session = False)
		groupchats.delete(synchronize_session = False)
		sess.flush()

if __name__ == '__main__':
	import funcli
	funcli.main()
