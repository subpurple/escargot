from sqlaltery import ops
import sqlalchemy as sa

from util.json_type import JSONType

OPS = [
	ops.AddTable('t_sound', (
		sa.Column('category', sa.Integer(), nullable=False),
		sa.Column('hash', sa.String(), nullable=False, primary_key=True),
		sa.Column('is_public', sa.Boolean(), nullable=False),
		sa.Column('language', sa.Integer(), nullable=False),
		sa.Column('title', sa.String(), nullable=False),
	)),
	ops.AddTable('t_user', (
		sa.Column('contacts', JSONType(), nullable=False),
		sa.Column('date_created', sa.DateTime()),
		sa.Column('date_login', sa.DateTime()),
		sa.Column('email', sa.String(), nullable=False, unique=True),
		sa.Column('groups', JSONType(), nullable=False),
		sa.Column('id', sa.Integer(), nullable=False, primary_key=True),
		sa.Column('message', sa.String(), nullable=False),
		sa.Column('name', sa.String(), nullable=False),
		sa.Column('password', sa.String(), nullable=False),
		sa.Column('settings', JSONType(), nullable=False),
		sa.Column('type', sa.Integer(), nullable=False),
		sa.Column('uuid', sa.String(), nullable=False, unique=True),
		sa.Column('verified', sa.Boolean(), nullable=False),
	)),
]
