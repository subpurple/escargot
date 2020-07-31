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
	# TODO: Less clunky way of doing this
	#ops.DataOperation(lambda md, conn: (
	#	conn.execute(md.tables['t_user'].update().where(md.tables['t_user'].c.groups != '').values(groups = _update_groups(md.tables['t_user'].c.groups)))
	#)),
]

# TODO: Dunno how clean this function is, review at some point
#def _update_groups(groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
#	new_groups = []
#	group_name_count = {}
#	for group in groups:
#		group['uuid'] = gen_uuid()
#		name = group['name']
#		if name in group_name_count:
#			i = group_name_count[name] + 1
#			group_name_count[name] = i
#			group['name'] = "{name}{i}".format(name = name, i = i)
#		else:
#			group_name_count[name] = 0
#		new_groups.append(group)
#	return new_groups