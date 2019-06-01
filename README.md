# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct and/or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP18 are implemented. Its been tested and works with MSN 1 through WLM 2009, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- Circles/Groups for WLM 2009 are partially implemented. Creation, invitations, and presence work. Messaging, group settings, and leaving Circles haven't been implemented yet.

YMSG:

As of now, only YMSG9 and YMSG10 are implemented. It has only been tested on three Yahoo! Messenger 5.5 builds, 1237, 1244, and 1246.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
