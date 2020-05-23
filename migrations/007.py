from sqlaltery import ops
import sqlalchemy as sa

OPS = [
	ops.AddColumn('t_user', sa.Column('username', sa.String(), nullable=False)),
	ops.AddIndex('t_user', (), name='username_ci_index', unique=True),
]
