import asyncio
import os
import random
import struct
import settings

from array import array
from core.backend import Backend
from dataclasses import dataclass
from html import escape
from typing import Optional, Any
from util.misc import Logger


@dataclass
class TLV:
    type: int
    data: bytes

    def __init__(self, type: int, data: bytes):
        self.type = type
        self.data = data


def decode_tlvs(data: bytes) -> list[TLV]:
    tlvs = []

    while len(data) > 4:
        type, length = struct.unpack('>HH', data[0:4])
        value = data[4:length + 4]

        tlvs.append(TLV(type, value))
        data = data[length + 4:]

    return tlvs


def encode_tlvs(tlvs: list[TLV]) -> bytes:
    data = b''
    for tlv in tlvs:
        data += struct.pack('>HH', tlv.type, len(tlv.data)) + tlv.data

    return data


def find_tlv(tlvs: list[TLV], type: int):
    for tlv in tlvs:
        if tlv.type == type:
            return tlv

    return None


class OSCARCtrl:
    logger: Logger
    transport: Optional[asyncio.WriteTransport]

    sequence: int = random.randint(0x0000, 0xFFFF)

    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self.transport = None

    def send_specific_frame(self, frame: int, data: bytes) -> None:
        if self.sequence == 0xFFFF:
            self.sequence = 0x0000
        else:
            self.sequence += 1

        packet = struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)) + data
        # self.logger.info('<<< Sending:', packet.hex())
        self.transport.write(packet)

    # TODO(subpurple): include flags and request id
    def send_snac(self, foodgroup: int, subgroup: int, data: bytes | list[TLV]) -> None:
        snac_header = struct.pack('>HHHL', foodgroup, subgroup, 0, 0)

        if isinstance(data, bytes):
            self.send_specific_frame(0x02, snac_header + data)
        else:
            self.send_specific_frame(0x02, snac_header + encode_tlvs(data))

    def on_connect(self) -> None:
        self.send_specific_frame(0x01, bytearray.fromhex('00 00 00 01'.replace(' ', '')))

    def on_signon_frame(self, data: bytes) -> None:
        # TODO(subpurple): support FLAP-level authentication aswell 
        if len(data) > 4:
            tlvs = decode_tlvs(data[4:])

            # TODO(subpurple): check the BOS cookie
            if find_tlv(tlvs, 0x0006):
                self.logger.info('<<< OSERVICE__HOST_ONLINE')
                self.send_snac(0x0001, 0x0003, struct.pack('>HH',
                                                           0x0001,  # OSERVICE
                                                           0x0005  # ADVERT
                                                           ))

    def on_data_frame(self, foodgroup: int, subgroup: int, flags: int, request_id: int, snac_data: bytes) -> None:
        # TODO(subpurple): care about the flags and request id

        match (foodgroup, subgroup):
            case (0x0017, 0x0006):
                self.logger.info('>>> BUCP__CHALLENGE_REQUEST')

                key = str(int.from_bytes(os.urandom(4)))

                self.logger.info('<<< BUCP__CHALLENGE_RESPONSE (key:', key + ')')
                self.send_snac(0x0017, 0x0007, struct.pack('>H', 10) + key.encode())

            case (0x0017, 0x0002):
                self.logger.info('>>> BUCP__LOGIN_REQUEST')

                tlvs = decode_tlvs(snac_data)

                screen_name_tlv = find_tlv(tlvs, 0x0001)
                hashed_pw_tlv = find_tlv(tlvs, 0x0025)

                screen_name = screen_name_tlv.data.decode()

                self.logger.info('>>> Screen Name:', screen_name)
                self.logger.info('>>> Password (hashed):', hashed_pw_tlv.data)

                email = f'{screen_name}@aol.com'
                password_change_url = f'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={escape(screen_name)}&ccode=us&lang=en'

                # TODO(subpurple): actually authorize the user
                if True:
                    self.logger.info('<<< BUCP__LOGIN_RESPONSE (authorized)')
                    self.send_snac(0x0017, 0x0003, [
                        TLV(0x0005, settings.TARGET_HOST.encode()),     # BOS address
                        TLV(0x0006, os.urandom(256)),                   # BOS authorization cookie
                        TLV(0x0011, email.encode()),                    # User's e-mail address
                        TLV(0x0013, struct.pack('>H', 1)),              # Registration status
                        TLV(0x0054, password_change_url.encode()),      # Password change URL
                        TLV(0x008E, b'\0'),                             # Unknown
                        TLV(0x0001, screen_name.encode())               # Screen name
                    ])
                else:
                    self.logger.info('<<< BUCP__LOGIN_RESPONSE (unauthorized)')

                    error_code = 0x0001  # 0x0001 = Unregistered Screenname, 0x0005 = Mismatched Password
                    error_url = \
                        "http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html" \
                            if error_code == 0x0001 \
                            else "http://www.aim.aol.com/errors/MISMATCH_PASSWD.html"

                    self.send_snac(0x0017, 0x0003, [
                        TLV(0x0008, struct.pack('>H', error_code)),
                        TLV(0x0004, error_url.encode()),
                        TLV(0x0001, screen_name.encode())
                    ])

            case _:
                self.logger.info('Recieved unknown SNAC with foodgroup:', hex(foodgroup), 'and subgroup:',
                                 hex(subgroup))
                self.logger.info('Data:', snac_data.hex())

    def on_error_frame(self, data: bytes) -> None:
        self.logger.info('Recieved error frame with:', data.hex())

    def on_signoff_frame(self, data: bytes) -> None:
        self.logger.info('Recieved signoff frame with:', data.hex())

    def close(self, **kwargs: Any) -> None:
        pass
