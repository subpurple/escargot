# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct and/or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP18 are implemented. Its been tested and works with MSN 1 through WLM 2009, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- `X has added you to their list` messages don't work on WLM 2009 and 2011. WLM 2012 hasn't been tested for this yet.

- Circles/Groups for WLM 2009 aren't implemented yet. This is being planned for implementation.

YMSG:

As of now, only YMSG9 and YMSG10 are implemented. It has only been tested on three Yahoo! Messenger 5.5 builds, 1237, 1244, and 1246.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
