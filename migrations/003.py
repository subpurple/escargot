from sqlaltery import ops
import sqlalchemy as sa

from util.json_type import JSONType

OPS = [
	ops.AddColumn('t_user', sa.Column('front_data', JSONType(), server_default='{}', nullable=False)),
]
