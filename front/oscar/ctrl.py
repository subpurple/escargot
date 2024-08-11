import asyncio
import os
import random
import struct
import settings

from array import array
from core.backend import Backend, BackendSession
from core.client import Client
from core.models import LoginOption
from itertools import cycle
from typing import Optional, Callable
from util.misc import Logger
from urllib.parse import quote

from .misc.backend import BackendEventHandler
from .misc.snac import OSCARClient, OSCARContext, SNACMessage, foodgroups
from .misc.tlv import TLV, marshal_tlvs, unmarshal_tlvs, find_tlv

bos_cookies: array[{bytes, OSCARContext}] = []
foodgroup_versions: {int, int} = {
    0x0001: 4,  # OSERVICE
    0x0002: 1,  # LOCATE
    0x0003: 1,  # BUDDY
    0x0004: 1,  # ICBM
    0x0006: 1,  # INVITE
    0x0008: 1,  # POPUP
    0x0009: 1,  # BOS
    0x000A: 1,  # USER_LOOKUP
    0x000B: 1,  # STATS
    0x000C: 1,  # TRANSLATE
    0x0013: 6,  # FEEDBAG
    0x0015: 2,  # ICQ
    0x0022: 1,  # PLUGIN
    0x0024: 1,  # UNNAMED (possibly NACHOS?)
    0x0025: 1   # MDIR
}

pw_change_url_format = 'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={}&ccode=us&lang=en'


# TODO(subpurple): as the foodgroups are no longer handled just in this file, might want to combine this and entry
class OSCARCtrl:
    logger: Logger
    transport: Optional[asyncio.WriteTransport]

    close_callback: Optional[Callable[[], None]]
    closed: bool

    backend: Backend
    bs: Optional[BackendSession]

    client: Client

    oscarClient: OSCARClient
    context: OSCARContext
    sequence: int = random.randint(0x0000, 0xFFFF)

    def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
        self.logger = logger
        self.transport = None

        self.close_callback = None
        self.closed = False

        self.backend = backend
        self.bs = None
        self.client = Client('oscar', '?', via)

        self.context = OSCARContext(self.backend, self.client)
        self.oscarClient = OSCARClient(self)

    def send_specific_frame(self, frame: int, data: bytes) -> None:
        if self.sequence == 0xFFFF:
            self.sequence = 0x0000
        else:
            self.sequence += 1

        packet = b''.join([
            struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)),
            data
        ])

        self.transport.write(packet)

    def send_snac(self, msg: SNACMessage) -> None:
        self.send_specific_frame(0x02, msg.marshal())

    def on_connect(self) -> None:
        self.send_specific_frame(0x01, struct.pack('>L', 1))

    def on_signon_frame(self, data: bytes) -> None:
        if len(data) > 4:
            global foodgroup_versions
            global bos_cookies

            tlvs = unmarshal_tlvs(data[4:])

            if (cookie_tlv := find_tlv(tlvs, 0x0006)) is not None:
                found = False

                for i, d in enumerate(bos_cookies):
                    for cookie, context in d.items():
                        if cookie == cookie_tlv.data:
                            self.logger.info('>>> Found BOS cookie')

                            self.context = context
                            self.context.backend = self.backend

                            self.bs = self.context.bs
                            self.bs.client = self.client
                            self.bs.backend = self.backend

                            bos_cookies.pop(i)
                            found = True

                if found:
                    # NINA also sends OSERVICE__WELL_KNOWN_URLS right after (should we?)
                    self.logger.info('<<< OSERVICE__HOST_ONLINE')

                    msg = SNACMessage(0x0001, 0x0003)

                    for foodgroup in foodgroup_versions.keys():
                        msg.write_u16(foodgroup)

                    self.send_snac(msg)
                else:
                    self.logger.info('invalid BOS cookie given')

            else:
                self.logger.info('>>> Using FLAP-level authentication')

                # [TLV(type=1, data=b'toxidation'),
                #  TLV(type=2, data=b'\x92'),
                #  TLV(type=3, data=b'AOL Instant Messenger (SM), version 3.0.1466/WIN32'),
                #  TLV(type=22, data=b'\x00\x04'),
                #  TLV(type=23, data=b'\x00\x03'),
                #  TLV(type=24, data=b'\x00\x00'),
                #  TLV(type=25, data=b'\x00\x00'),
                #  TLV(type=26, data=b'\x05\xba'),
                #  TLV(type=14, data=b'us'),
                #  TLV(type=15, data=b'en'),
                #  TLV(type=20, data=b'\x00\x00\x00-'),
                #  TLV(type=9, data=b'\x00\x15')]
                #
                # All we really care about here (for now) is 0x0001 and 0x0002:
                #   - 0x0001: screen name
                #   - 0x0002: roasted password

                screen_name_tlv = find_tlv(tlvs, 0x0001)
                roasted_pw_tlv = find_tlv(tlvs, 0x0002)

                screen_name = screen_name_tlv.data.decode()
                roasted_pw = roasted_pw_tlv.data

                self.logger.info('>>> Screen Name:', screen_name)
                self.logger.info('>>> Password (roasted):', roasted_pw.hex())

                context = self.context
                error_code, error_url = None, None

                if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
                    error_code = 0x0001
                    error_url = 'http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html'

                    self.logger.info('>>> Unregistered screenname')
                elif not context.backend.user_service.aim_login_flap(screen_name, roasted_pw):
                    error_code = 0x0005
                    error_url = 'http://www.aim.aol.com/errors/MISMATCH_PASSWD.html'

                    self.logger.info('>>> Incorrect password')

                if error_code is None:
                    self.logger.info('>>>', screen_name, 'logged in!')

                    context.bs = context.backend.login(uuid,
                                                       context.client,
                                                       BackendEventHandler(self),
                                                       option=LoginOption.NotifyOthers)
                    context.user = context.bs.user

                    bos_cookie = os.urandom(256)
                    bos_cookies.append({bos_cookie: self.context})

                    screen_name = context.user.username
                    email = context.user.email

                    self.logger.info('Screen Name (normalized):', screen_name)
                    self.logger.info('E-mail:', email)

                    self.send_specific_frame(0x04, marshal_tlvs([
                        TLV(0x0001, screen_name),                               # Screen name
                        TLV(0x0005, f'{settings.TARGET_HOST}:5190'),            # BOS address
                        TLV(0x0006, bos_cookie),                                # BOS authorization cookie
                        TLV(0x0011, email),                                     # User's e-mail address
                        TLV(0x0013, struct.pack('>H', 1)),                      # Registration status
                        TLV(0x0054, pw_change_url_format.format(screen_name)),  # Password change URL
                        TLV(0x008E, b'\0'),                                     # Unknown
                    ]))
                else:
                    self.logger.info('>>> Incorrect username or password')

                    self.send_specific_frame(0x04, marshal_tlvs([
                        TLV(0x0001, screen_name),                    # Screen name
                        TLV(0x0008, struct.pack('>H', error_code)),  # Error code
                        TLV(0x0004, error_url),                      # Error URL
                    ]))

    def on_data_frame(self, message: SNACMessage) -> None:
        found = False

        # kick client off if we haven't authenticated and client is trying to access something outside of BUCP
        if message.foodgroup != 0x0017 and self.bs is None:
            self.close()
            return

        for value, cls in foodgroups.items():
            if value == message.foodgroup:
                if not hasattr(cls, 'logger'):
                    cls.logger = self.logger

                if message.subgroup in cls.subgroups:
                    found = True

                    func = cls.subgroups[message.subgroup]
                    func(cls, self.oscarClient, self.context, message)

        if not found:
            self.logger.info(f'>>> Unknown SNAC({hex(message.foodgroup)},{hex(message.subgroup)})')
            self.logger.info(message.data.hex())

    def on_error_frame(self, data: bytes) -> None:
        self.logger.info('>>> Recieved error frame with:', data.hex())

    def on_signoff_frame(self, data: bytes) -> None:
        self.logger.info('>>> Recieved signoff frame')

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True

        if self.close_callback:
            self.close_callback()
