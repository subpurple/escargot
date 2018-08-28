# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP15 (with experimental MSNP16/18 support) are implemented. Its been tested and works with MSN 1 through WLM 2009/14, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- Messaging works with MSNP18. NS presence is OK, but login toasts are very hit or miss with WLM 2009. MPoP features haven't been properly tested yet, and PSMs aren't loaded with newly logged-in accounts on WLM 2009, but are retained if set in WLM 2009.

YMSG:

As of now, only YMSG10 is implemented. It has only been tested on two Yahoo! Messenger 5.5 builds, 1237 and 1244.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
