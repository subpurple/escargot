from sqlaltery import ops
import sqlalchemy as sa

from util.json_type import JSONType

OPS = [
	ops.DropColumn('t_user', 'type'),
	ops.AddColumn('t_user', sa.Column('front_data', JSONType(), server_default='{}', nullable=False)),
	ops.DataOperation('''
		UPDATE t_user
		SET front_data = ('{"msn":{"pw_md5":"' || password_md5 || '"}}')
		WHERE password_md5 != ''
	'''),
]
