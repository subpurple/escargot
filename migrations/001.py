from sqlaltery import ops
import sqlalchemy as sa

from core.db import Col
from util.json_type import JSONType

OPS = [
	ops.AddTable('t_sound', (
		Col('category', sa.Integer()),
		Col('hash', sa.String(), primary_key=True),
		Col('is_public', sa.Boolean()),
		Col('language', sa.Integer()),
		Col('title', sa.String()),
	)),
	ops.AddTable('t_user', (
		Col('date_created', sa.DateTime()),
		Col('date_login', sa.DateTime(), nullable=True),
		Col('email', sa.String(), unique=True),
		Col('groups', JSONType()),
		Col('id', sa.Integer(), primary_key=True),
		Col('message', sa.String()),
		Col('name', sa.String()),
		Col('password', sa.String()),
		Col('settings', JSONType()),
		Col('type', sa.Integer()),
		Col('uuid', sa.String(), unique=True),
		Col('verified', sa.Boolean()),
	)),
]
