from sqlaltery import ops
import sqlalchemy as sa

OPS = [
	ops.AddColumn('t_user', sa.Column('password_md5', sa.String(), nullable=False, server_default='')),
]
