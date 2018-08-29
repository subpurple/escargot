import db
import sys

with db.Session() as sess:
	# TODO: How delete column in SQLite?; Spit out notice to user to manually recreate the DB for now.
	# sess.execute('''
	# 	ALTER TABLE t_user DROP COLUMN type
	# ''')
	print('''Since this revision of `dbmigrate.py` is supposed to involve deleting an unneeded column from the database table `t_user`, something the default DB engine (SQLite) doesn't support, we advise you to manually recreate the database table with the offending column unspecified.''')
	sys.exit(-1)
	#sess.execute('''
	#	ALTER TABLE t_user ADD COLUMN front_data TEXT NOT NULL DEFAULT '{}'
	#''')
	#sess.execute('''
	#	UPDATE t_user
	#	SET front_data = ('{"msn":{"pw_md5":"' || password_md5 || '"}}')
	#	WHERE password_md5 != ''
	#''')
