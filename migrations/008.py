from sqlaltery import ops
import sqlalchemy as sa
from util.json_type import JSONType

OPS = [
	ops.DropUnique('t_user', None),
	ops.AddTable('t_login_token', (
		sa.Column('data', JSONType(), nullable=False),
		sa.Column('expiry', sa.DateTime(), nullable=False),
		sa.Column('id', sa.Integer(), nullable=False),
		sa.Column('purpose', sa.String(), nullable=False),
		sa.Column('token', sa.String(), nullable=False),
	)),
	ops.AddPrimaryKey('t_login_token', ('id',)),
	ops.AddUnique('t_user', ('uuid',)),
]
