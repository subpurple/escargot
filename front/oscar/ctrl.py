import asyncio
import random
import struct

from typing import Optional, Any
from util.misc import Logger
from .misc import OSCARClient, SNACMessage, decode_tlvs, find_tlv, foodgroups

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


# TODO(subpurple): as the foodgroups are no longer handled just in this file, might want to combine this and entry
class OSCARCtrl:
    logger: Logger
    transport: Optional[asyncio.WriteTransport]
    client: OSCARClient

    sequence: int = random.randint(0x0000, 0xFFFF)

    def __init__(self, logger: Logger) -> None:
        self.logger = logger
        self.transport = None
        self.client = OSCARClient(self)

    def send_specific_frame(self, frame: int, data: bytes) -> None:
        if self.sequence == 0xFFFF:
            self.sequence = 0x0000
        else:
            self.sequence += 1

        packet = struct.pack('>BBHH', 0x2A, frame, self.sequence, len(data)) + data
        self.transport.write(packet)

    def send_snac(self, msg: SNACMessage) -> None:
        self.send_specific_frame(0x02, msg.marshal())

    def on_connect(self) -> None:
        self.send_specific_frame(0x01, bytearray.fromhex('00 00 00 01'.replace(' ', '')))

    def on_signon_frame(self, data: bytes) -> None:
        # TODO(subpurple): support FLAP-level authentication aswell 
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
        self.logger.info('Recieved error frame with:', data.hex())

    def on_signoff_frame(self, data: bytes) -> None:
        self.logger.info('Recieved signoff frame with:', data.hex())

    def close(self, **kwargs: Any) -> None:
        pass
