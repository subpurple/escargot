import json
from sqlalchemy import types
from sqlalchemy.dialects import postgresql

class JSONType(types.TypeDecorator): # type: ignore
	impl = types.TEXT
	
	def load_dialect_impl(self, dialect):
		if dialect.name == 'postgresql':
			t = postgresql.JSONB()
		else:
			t = types.TEXT()
		return dialect.type_descriptor(t)
	
	def process_bind_param(self, value, dialect):
		if value is None or dialect.name == 'postgresql':
			return value
		return json.dumps(value)
	
	def process_result_value(self, value, dialect):
		if value is None or dialect.name == 'postgresql':
			return value
		return json.loads(value)
