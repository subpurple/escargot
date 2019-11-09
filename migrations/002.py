from sqlaltery import ops
import sqlalchemy as sa

from core.db import Col
from util.json_type import JSONType

OPS = [
	ops.AddColumn('t_user', Col('contacts', JSONType())),
	ops.AddColumn('t_user', Col('password_md5', sa.String(), server_default='')),
]
