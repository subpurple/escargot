from sqlaltery import ops
import sqlalchemy as sa

OPS = [
	ops.DropUnique('t_user', None),
	ops.DropPrimaryKey('t_user_contact'),
	ops.DropColumn('t_group_chat_membership', 'inviter_message'),
	ops.AddColumn('t_group_chat_membership', sa.Column('invite_message', sa.String())),
	ops.AddColumn('t_user_contact', sa.Column('work_email', sa.String())),
	ops.AddIndex('t_user', (), name='email_ci_index', unique=True),
	ops.AddPrimaryKey('t_user_contact', ('user_id', 'contact_id')),
	ops.AlterColumn('t_user', 'front_data', server_default=None),
	ops.AlterColumn('t_user', 'name', nullable=True),
	ops.AlterColumn('t_user_contact', 'front_data', server_default=None),
	ops.AlterColumn('t_user_contact', 'groups', server_default=None),
	ops.AlterColumn('t_user_contact', 'locations', server_default=None),
]
