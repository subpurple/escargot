# Escargot Messaging Server

This is a server planning to support as many messaging platforms and technologies as possible. Support is planned for every messaging platform/technology that is either defunct and/or suitable for federation.

See [escargot.log1p.xyz](https://escargot.log1p.xyz) for instructions on how to connect.


## Support status

MSNP:

Currently, MSNP2 through MSNP18 (with experimental MSNP21 support) are implemented. Its been tested and works with MSN 1 through WLM 2011, with some caveats:

- Because of MSNP limitations, if you want to log in to MSN < 5, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`)

- `X has added you to their list` messages don't work on WLM 2009 and 2011. WLM 2012 hasn't been tested for this yet.

- Authentication, contact lists, and presence work on MSNP21 (granted you don't use Windows 8 - 10, which encrypt RST requests). Statuses haven't been fully implemented, display pictures haven't been tested yet, and messaging and multiparties don't work.

YMSG:

As of now, only YMSG9 and YMSG10 are implemented. It has only been tested on two Yahoo! Messenger 5.5 builds, 1237 and 1244.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
