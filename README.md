# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP15 are implemented. Its been tested and works with MSN 1 through MSN 8.5, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

YMSG:

As of now, only YMSG10 is implemented. It has only been tested on two Yahoo! Messenger 5.5 builds, 1237 and 1244.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
