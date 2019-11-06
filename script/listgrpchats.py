from core import db

def main(*, verbose: bool = False) -> None:
	total = 0
	with db.Session() as sess:
		for gc in sess.query(db.GroupChat).all():
			total += 1
			if verbose:
				print(gc.chat_id, gc.name)
	
	print("Total:", total)

if __name__ == '__main__':
	import funcli
	funcli.main()
