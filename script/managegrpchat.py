from core import db
from core.conn import Conn
import settings

def main(id: str, action: str, *args: str) -> None:
	memberships_to_add = []
	conn = Conn(settings.DB)
	with conn.session() as sess:
		gc = sess.query(db.GroupChat).filter(db.GroupChat.chat_id == id).one_or_none()
		if gc is None:
			print('Group chat {} does not exist'.format(id))
			return
		if action.lower() == 'role':
			if len(args) < 2:
				print('Insufficient arguments for action role')
				return
			email = args[0]
			role = args[1]
			
			user = sess.query(db.User).filter(db.User.email == email).one_or_none()
			if user is None:
				print('role: User {} does not exist'.format(email))
				return
			m = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id == gc.chat_id, db.GroupChatMembership.member_id == user.id).one_or_none()
			if m is None:
				print('role: User {} not a member in group chat'.format(user.email))
				return
			
			if m.state != 3:
				print('role: User {}\'s role in group chat is not set to accepted'.format(user.email))
				return
			elif m.role == 1:
				print('role: User {} is an owner in group chat and cannot be set to any other role. Use "owner" to transfer their ownership to someone else'.format(user.email))
				return
			if role not in ('2','3'):
				if role == '1':
					print('role: Cannot set user {}\'s group chat role to owner with this command. Use "owner" to perform this action'.format(user.email))
				else:
					print('role: Role specified is not valid. Accepted values are 2 (co-owner) and 3 (member)')
				return
			
			m.role = int(role)
			memberships_to_add.append(m)
		elif action.lower() == 'owner':
			if len(args) < 1:
				print('Insufficient arguments for action owner')
				return
			email = args[0]
			
			user = sess.query(db.User).filter(db.User.email == email).one_or_none()
			if user is None:
				print('owner: User {} does not exist'.format(email))
				return
			m = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id == gc.chat_id, db.GroupChatMembership.member_id == user.id).one_or_none()
			if m is None:
				print('role: User {} not a member in group chat'.format(user.email))
				return
			
			if m.state != 3:
				print('owner: User {}\'s role in group chat is not set to accepted'.format(user.email))
				return
			if m.role == 1:
				print('owner: User {} is already owner'.format(user.email))
				return
			
			m_owner = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id == gc.chat_id, db.GroupChatMembership.role == 1).one_or_none()
			if m_owner is not None:
				m_owner.role = 3
			m.role = 1
			memberships_to_add.append(m)
			if m_owner is not None:
				memberships_to_add.append(m_owner)
		elif action.lower() == 'remove':
			if len(args) < 1:
				print('Insufficient arguments for action remove')
				return
			email = args[0]
			
			user = sess.query(db.User).filter(db.User.email == email).one_or_none()
			if user is None:
				print('remove: User {} does not exist'.format(email))
				return
			m = sess.query(db.GroupChatMembership).filter(db.GroupChatMembership.chat_id == gc.chat_id, db.GroupChatMembership.member_id == user.id).one_or_none()
			if m is None or m.state == 0:
				print('remove: User {} not a member in group chat'.format(user.email))
				return
			if m.role == 1:
				print('remove: User {} is an owner and cannot be removed from group chat'.format(user.email))
				return
			
			m.role = 3
			m.state = 0
			memberships_to_add.append(m)
		else:
			print('Invalid action')
			
		if memberships_to_add:
			sess.add_all(memberships_to_add)
			sess.flush()
			print('Action successfully performed')

if __name__ == '__main__':
	import funcli
	funcli.main()
