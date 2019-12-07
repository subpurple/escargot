from sqlaltery import ops
import sqlalchemy as sa

from typing import List, Dict, Any
from core.db import Col
from util.json_type import JSONType
from util.misc import gen_uuid

OPS = [
	ops.DropTable('t_sound'),
	ops.DropColumn('t_user', 'type'),
	ops.AddColumn('t_user', Col('front_data', JSONType(), server_default='{}')),
	ops.DataOperation('''
		UPDATE t_user
		SET front_data = ('{"msn":{"pw_md5":"' || password_md5 || '"}}')
		WHERE password_md5 != ''
	'''),
	ops.DataOperation(lambda md, conn: (
		conn.execute(md.tables['t_user'].update().where(md.tables['t_user'].c.groups != '').values(groups = _add_uuid_to_groups(md.tables['t_user'].c.groups)))
	)),
]

def _add_uuid_to_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	new_groups = []
	for group in groups:
		group['uuid'] = gen_uuid()
		new_groups.append(group)
	return new_groups