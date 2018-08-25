# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP15 (with experimental MSNP16/18 support) are implemented. Its been tested and works with MSN 1 through WLM 2009/14, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- Messaging works with MSNP18, but SOAP contact management (adding, moving, and deleting contacts) isn't 100% working and NS presence is very hit or miss with WLM 2009. Avatar and MPoP features haven't been tested yet. WLM 2009 PSMs, scenes and DDPs (Dynamic Display Pictures) aren't implemented server-side.

YMSG:

As of now, only YMSG10 is implemented. It has only been tested on two Yahoo! Messenger 5.5 builds, 1237 and 1244.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
