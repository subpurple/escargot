from sqlaltery import ops
import sqlalchemy as sa

from core.db import Col
from util.json_type import JSONType

OPS = [
	ops.DropTable('t_sound'),
	ops.DropColumn('t_user', 'type'),
	ops.AddColumn('t_user', Col('front_data', JSONType(), server_default='{}')),
	ops.DataOperation('''
		UPDATE t_user
		SET front_data = ('{"msn":{"pw_md5":"' || password_md5 || '"}}')
		WHERE password_md5 != ''
	'''),
]
