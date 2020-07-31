from sqlaltery import ops
import sqlalchemy as sa
from sqlalchemy.schema import MetaData
from sqlalchemy.engine import Connectable

from core import db
from core.db import Col
from util.json_type import JSONType

OPS = [
	ops.DropColumn('t_user', 'password_md5'),
	ops.AddTable('t_user_contact', (
		Col('anniversary', sa.DateTime(), nullable = True),
		Col('birthdate', sa.DateTime(), nullable = True),
		Col('business_website', sa.String(), nullable = True),
		Col('contact_id', sa.Integer(), sa.ForeignKey('t_user.id'), primary_key = True),
		Col('fax_phone', sa.String(), nullable = True),
		Col('first_name', sa.String(), nullable = True),
		Col('front_data', JSONType(), server_default='{}'),
		Col('groups', JSONType(), server_default='{}'),
		Col('home_phone', sa.String(), nullable = True),
		Col('im_email', sa.String(), nullable = True),
		Col('index_id', sa.String()),
		Col('is_messenger_user', sa.Boolean()),
		Col('last_name', sa.String(), nullable = True),
		Col('lists', sa.Integer()),
		Col('locations', JSONType(), server_default='{}'),
		Col('middle_name', sa.String(), nullable = True),
		Col('mobile_phone', sa.String(), nullable = True),
		Col('name', sa.String()),
		Col('nickname', sa.String(), nullable = True),
		Col('notes', sa.String(), nullable = True),
		Col('other_email', sa.String(), nullable = True),
		Col('other_phone', sa.String(), nullable = True),
		Col('pager_phone', sa.String(), nullable = True),
		Col('pending', sa.Boolean(), default = False),
		Col('personal_email', sa.String(), nullable = True),
		Col('personal_website', sa.String(), nullable = True),
		Col('primary_email_type', sa.String(), nullable = True),
		Col('user_id', sa.Integer(), sa.ForeignKey('t_user.id'), primary_key = True),
		Col('user_uuid', sa.String(), sa.ForeignKey('t_user.uuid')),
		Col('uuid', sa.String(), sa.ForeignKey('t_user.uuid')),
		Col('work_phone', sa.String(), nullable = True),
	)),
	ops.DataOperation(lambda md, conn: (
		_migrate_contact_data(md, conn)
	)),
	ops.AddTable('t_group_chat', (
		Col('chat_id', sa.String(), unique = True),
		Col('id', sa.Integer(), primary_key = True),
		Col('membership_access', sa.Integer()),
		Col('name', sa.String()),
		Col('owner_friendly', sa.String()),
		Col('owner_id', sa.Integer(), sa.ForeignKey('t_user.id')),
		Col('owner_uuid', sa.String(), sa.ForeignKey('t_user.uuid')),
		Col('request_membership_option', sa.Integer()),
	)),
	ops.AddTable('t_group_chat_membership', (
		Col('blocking', sa.Boolean()),
		Col('chat_id', sa.String(), sa.ForeignKey('t_group_chat.chat_id')),
		Col('id', sa.Integer(), primary_key = True),
		Col('inviter_email', sa.String(), nullable = True),
		Col('inviter_message', sa.String(), nullable = True),
		Col('inviter_name', sa.String(), nullable = True),
		Col('inviter_uuid', sa.String(), nullable = True),
		Col('member_id', sa.Integer(), sa.ForeignKey('t_user.id')),
		Col('member_uuid', sa.String(), sa.ForeignKey('t_user.uuid')),
		Col('role', sa.Integer()),
		Col('state', sa.Integer()),
	)),
]

def _migrate_contact_data(md: MetaData, conn: Connectable) -> None:
	users = md.tables['t_user']
	for id, uuid, contacts, groups in conn.execute(sa.select([users.c.id, users.c.uuid, users.c.contacts, users.c.groups]).where(users.c.contacts != '')).fetchall():
		i = 2
		for c in contacts:
			contact_id = conn.execute(sa.select([users.c.id]).where(users.c.uuid == c['uuid'])).fetchone()
			if contact_id is None: continue
			new_groups = []
			for group_id in c['groups']:
				contact_group = None
				for group in groups:
					if group['id'] == group_id:
						contact_group = group
						break
				if contact_group is None: continue
				new_groups.append({
					'id': contact_group['id'],
					'uuid': contact_group['uuid'],
				})
			conn.execute(md.tables['t_user_contact'].insert().values(
				user_id = id, user_uuid = uuid,
				uuid = c['uuid'], contact_id = contact_id[0], index_id = str(i + 2),
				groups = new_groups, is_messenger_user = (c.get('is_messenger_user') or False), lists = c['lists'], message = c['message'], name = c['name'],
			))
			i += 1