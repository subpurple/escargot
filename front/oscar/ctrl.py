import asyncio
import random
import struct

from core.backend import Backend, BackendSession
from core.client import Client
from core.models import LoginOption
from typing import Optional, Callable
from util.misc import Logger

from .misc.backend import BackendEventHandler, FOODGROUP_VERSIONS, login, bos_cookies
from .misc.snac import OSCARClient, OSCARContext, SNACMessage, foodgroups
from .misc.tlv import unmarshal_tlvs, find_tlv


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
            tlvs = unmarshal_tlvs(data[4:])

            if (cookie_tlv := find_tlv(tlvs, 0x0006)) is not None:
                found = False

                for i, d in enumerate(bos_cookies):
                    for cookie, uuid in d.items():
                        if cookie == cookie_tlv.data:
                            self.logger.info('found BOS cookie')

                            self.context.bs = self.backend.login(uuid,
                                                                 self.client,
                                                                 BackendEventHandler(self),
                                                                 option=LoginOption.NotifyOthers)
                            self.context.user = self.context.bs.user
                            self.bs = self.context.bs

                            bos_cookies.pop(i)
                            found = True

                if found:
                    # NINA also sends OSERVICE__WELL_KNOWN_URLS right after (should we?)
                    self.logger.info('<<< OSERVICE__HOST_ONLINE')

                    msg = SNACMessage(0x0001, 0x0003)

                    for foodgroup in FOODGROUP_VERSIONS.keys():
                        msg.write_u16(foodgroup)

                    self.send_snac(msg)
                else:
                    self.logger.info('invalid BOS cookie given')

            else:
                self.logger.info('Using FLAP-level authentication')

                screen_name_tlv = find_tlv(tlvs, 0x0001)
                roasted_pw_tlv = find_tlv(tlvs, 0x0002)

                screen_name = screen_name_tlv.data.decode()
                roasted_pw = roasted_pw_tlv.data

                self.logger.info('Screen Name (client-given):', screen_name)
                self.logger.info('Password (roasted):', roasted_pw.hex())

                context = self.context
                error_code = None

                if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
                    error_code = 0x0001

                    self.logger.info('Unregistered screenname')
                elif not context.backend.user_service.aim_login_flap(screen_name, roasted_pw):
                    error_code = 0x0005

                    self.logger.info('Incorrect password')

                self.send_specific_frame(0x04, login(self.logger, self.context, tlvs, uuid))

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
            self.logger.info('>>>', message.data.hex())

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
