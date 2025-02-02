# Escargot

> [!IMPORTANT]
> I'm no longer working on this Escargot fork, thus why I have archived it. Features I was originally working on like OSCAR or MySpaceIM, will instead be added to [CrossTalk](https://crosstalk.hiden.cc/) where I'm now a core developer. However, compared to this, CrossTalk is not open-source, but in the near future it may be.

This is a fork of the [original Escargot server](https://gitlab.com/escargot-chat/server) that plans to modernize and update the codebase, aswell as add new frontends for many more defunct messagers, such as for OSCAR (used by AOL Instant Messenger and ICQ) or MySpaceIM.

## Support status

- MSNP:
    - Only MSNP2 through MSNP18 are implemented, which has been tested and works with MSN 1.0 through WLM 2009, with some caveats:

        - Because of MSNP limitations, if you want to log in to MSN versions below 5.x, you have to store an MD5-encoded password (`User.front_data['msn']['pw_md5']`).

        - Some WLM 8 betas don't work with Escargot even though it supports their protocol mainly due to the way they login or subtle differences in the way they use services.

        - Circles/Groups for WLM 2009 are fully implemented. However, managing member roles is expected to be done from an external source (in Messenger's case, a website). Running `script/managegrpchat.py` will let you perform a few actions on a group chat and its users (run `python script/managegrpchat.py -h` to see instructions)

- YMSG:
    - As of now, only YMSG9 and YMSG10 are implemented. It has only been tested on Yahoo! Messenger 5.0.0.1066 and three Yahoo! Messenger 5.5 builds, 1237, 1244, and 1246.

- IRC:
    - IRC support is very basic. It only offers the ability to create, join, invite people to, leave, and list other people in temporary chats. It also requires `USER`-based login with your account credentials. Nicknames aren't supported.

## Developers

See [CONTRIBUTING.md](/CONTRIBUTING.md).
