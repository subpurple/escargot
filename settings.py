DB = 'sqlite:///escargot.sqlite'
STATS_DB = 'sqlite:///stats.sqlite'
CERT_DIR = 'path/to/cert'
CERT_ROOT = 'CERT_ROOT'
TARGET_HOST = 'm1.escargot.log1p.xyz'
LOGIN_HOST = 'm1.escargot.log1p.xyz'
STORAGE_HOST = LOGIN_HOST
# While not necessary for debugging, it is recommended you change the password variables in production for security reasons.
SYSBOARD_PASS = 'root'
SITE_LINK_PASSWORD = 'password'

DEBUG = False
DEBUG_MSNP = False
DEBUG_YMSG = False
DEBUG_IRC = False
DEBUG_S2S = False
DEBUG_HTTP_REQUEST = False
DEBUG_HTTP_REQUEST_FULL = False
DEBUG_SYSBOARD = True

ENABLE_S2S = False
ENABLE_FRONT_MSN = True
ENABLE_FRONT_YMSG = False
ENABLE_FRONT_IRC = False
ENABLE_FRONT_IRC_SSL = False
ENABLE_FRONT_API = False
ENABLE_FRONT_BOT = False
ENABLE_FRONT_DEVBOTS = False

SERVICE_KEYS = [] # type: ignore

try:
	from settings_local import *
except ImportError as ex:
	raise Exception("Please create settings_local.py") from ex
