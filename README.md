# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct and/or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP18 are implemented. Its been tested and works with MSN 1 through WLM 2009, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- Circles/Groups for WLM 2009 are fully implemented. However, managing member roles and leaving Circles are expected to be done from a website. You can either manually configure the memberships in the database yourself, or set up the [site](https://gitlab.com/escargot-chat/site/tree/patch/new-site) component if you want to quickly configure roles for testing.

YMSG:

As of now, only YMSG9 and YMSG10 are implemented. It has only been tested on three Yahoo! Messenger 5.5 builds, 1237, 1244, and 1246.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
