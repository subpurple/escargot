from sqlaltery import ops
import sqlalchemy as sa

OPS = [
	ops.AddColumn('t_user', sa.Column('friendly_name', sa.String(), nullable=False)),
	ops.AddColumn('t_user', sa.Column('message_last_modified', sa.DateTime(), nullable=False)),
	ops.AddColumn('t_user', sa.Column('name_last_modified', sa.DateTime(), nullable=False)),
	ops.AlterColumn('t_user', 'message', nullable=True),
]
