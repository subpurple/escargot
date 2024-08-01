import asyncio
import os
import random
import struct
import settings

from core.backend import Backend
from itertools import cycle
from typing import Optional, Any
from util.misc import Logger
from urllib.parse import quote
from .misc import OSCARClient, SNACMessage, TLV, encode_tlvs, decode_tlvs, find_tlv, foodgroups

authorize = False
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
    0x0025: 1  # MDIR
}


# Thanks https://homework.nwsnet.de/releases/9b1a/!
#
# TODO(subpurple): there is a different roasting chars for the Java client - implement those
def roast(password: bytes,
          key: bytes = b'\xF3\x26\x81\xC4\x39\x86\xDB\x92\x71\xA3\xB9\xE6\x53\x7A\x95\x7C') -> bytes:
    chars = cycle(key)
    return bytes(byte ^ next(chars) for byte in password)


# TODO(subpurple): as the foodgroups are no longer handled just in this file, might want to combine this and entry
class OSCARCtrl:
    logger: Logger
    backend: Backend
    transport: Optional[asyncio.WriteTransport]
    client: OSCARClient

    sequence: int = random.randint(0x0000, 0xFFFF)

    def __init__(self, logger: Logger, via: str, backend: Backend) -> None:
        self.logger = logger
        self.transport = None
        self.backend = backend
        self.client = OSCARClient(self)

    def send_specific_frame(self, frame: int, data: bytes) -> None:
        if self.sequence == 0xFFFF:
            self.sequence = 0x0000
        else:
            self.sequence += 1

        packet = b''.join([
            struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)),
            data
        ])

        # self.logger.info('>>> Frame:', frame)
        # self.logger.info('>>> Sequence:', self.sequence)
        # self.logger.info('>>> Data:', data.hex())
        # self.logger.info('>>>', packet.hex())

        self.transport.write(packet)

    def send_snac(self, msg: SNACMessage) -> None:
        self.send_specific_frame(0x02, msg.marshal())

    def on_connect(self) -> None:
        self.send_specific_frame(0x01, bytearray.fromhex('00 00 00 01'.replace(' ', '')))

    def on_signon_frame(self, data: bytes) -> None:
        if len(data) > 4:
            tlvs = decode_tlvs(data[4:])

            # TODO(subpurple): check the BOS cookie
            if find_tlv(tlvs, 0x0006):
                # NINA also sends OSERVICE__WELL_KNOWN_URLS right after (should we?)
                self.logger.info('<<< OSERVICE__HOST_ONLINE')

                msg = SNACMessage(0x0001, 0x0003)

                for foodgroup in foodgroup_versions.keys():
                    msg.add_u16(foodgroup_versions[foodgroup])

                self.send_snac(msg)

            # TODO(subpurple): actually authorize the user
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
                unroasted_pw = roast(roasted_pw).decode()

                self.logger.info('>>> Screen Name:', screen_name)
                self.logger.info('>>> Password (roasted):', roasted_pw)
                self.logger.info('>>> Password (unroasted):', unroasted_pw)

                email = f'{screen_name}@aol.com'
                password_change_url = f'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={quote(screen_name)}&ccode=us&lang=en'

                global authorize
                if authorize:
                    self.logger.info('>>>', screen_name, 'logged in!')
                    self.send_specific_frame(0x04, encode_tlvs([
                        TLV(0x0001, screen_name),                       # Screen name
                        TLV(0x0005, f'{settings.TARGET_HOST}:5190'),    # BOS address
                        TLV(0x0006, os.urandom(256)),                   # BOS authorization cookie
                        TLV(0x0011, email),                             # User's e-mail address
                        TLV(0x0013, struct.pack('>H', 1)),              # Registration status
                        TLV(0x0054, password_change_url),               # Password change URL
                        TLV(0x008E, b'\0'),                             # Unknown
                    ]))
                else:
                    self.logger.info('>>> Incorrect username or password')

                    # Error codes used here:
                    #   - 0x0001: Unregistered Screenname
                    #   - 0x0005: Mismatched Password
                    error_code = 0x0001
                    error_url = \
                        'http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html' \
                            if error_code == 0x0001 \
                            else 'http://www.aim.aol.com/errors/MISMATCH_PASSWD.html'

                    self.send_specific_frame(0x04, encode_tlvs([
                        TLV(0x0001, screen_name),                    # Screen name
                        TLV(0x0008, struct.pack('>H', error_code)),  # Error code
                        TLV(0x0004, error_url),                      # Error URL
                    ]))

    def on_data_frame(self, message: SNACMessage) -> None:
        found = False

        for value, cls in foodgroups.items():
            if value == message.foodgroup:
                if not hasattr(cls, 'logger'):
                    cls.logger = self.logger

                if message.subgroup in cls.subgroups:
                    found = True

                    func = cls.subgroups[message.subgroup]

                    # TODO(subpurple): pass real context that isn't just None
                    func(cls, self.client, None, message)

        if not found:
            self.logger.info(f'>>> Unknown SNAC({message.foodgroup},{message.subgroup})')
            self.logger.info(message.data.hex())

    def on_error_frame(self, data: bytes) -> None:
        self.logger.info('>>> Recieved error frame with:', data.hex())

    def on_signoff_frame(self, data: bytes) -> None:
        self.logger.info('>>> Recieved signoff frame with:', data.hex())

    def close(self, **kwargs: Any) -> None:
        pass
