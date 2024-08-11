import struct
import time

from ..ctrl import foodgroup_versions
from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..misc.tlv import TLV
from util.misc import Logger


@Foodgroup(0x0001)
class OSERVICEFoodgroup:
    logger: Logger

    @Subgroup(0x0017)
    def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> OSERVICE__CLIENT_VERSIONS')

        response_msg = SNACMessage(0x0001, 0x0018, 0x0000, 0x0000)
        for foodgroup, version in foodgroup_versions.items():
            response_msg.write_u16(foodgroup)
            response_msg.write_u16(version)

        self.logger.info('<<< OSERVICE__HOST_VERSIONS')
        client.send_snac(response_msg)

    @Subgroup(0x0006)
    def rate_params_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> OSERVICE__RATE_PARAMS_QUERY')

        hex = """
        00 05 00 01 00 00 00 50  00 00 09 C4 00 00 07 D0
        00 00 05 DC 00 00 03 20  00 00 0D 69 00 00 17 70
        00 00 00 00 00 00 02 00  00 00 50 00 00 0B B8 00
        00 07 D0 00 00 05 DC 00  00 03 E8 00 00 17 70 00
        00 17 70 00 00 F9 0B 00  00 03 00 00 00 14 00 00
        13 EC 00 00 13 88 00 00  0F A0 00 00 0B B8 00 00
        11 47 00 00 17 70 00 00  5C D8 00 00 04 00 00 00
        14 00 00 15 7C 00 00 14  B4 00 00 10 68 00 00 0B
        B8 00 00 17 70 00 00 1F  40 00 00 F9 0B 00 00 05
        00 00 00 0A 00 00 15 7C  00 00 14 B4 00 00 10 68
        00 00 0B B8 00 00 17 70  00 00 1F 40 00 00 F9 0B
        00 00 01 00 91 00 01 00  01 00 01 00 02 00 01 00
        03 00 01 00 04 00 01 00  05 00 01 00 06 00 01 00
        07 00 01 00 08 00 01 00  09 00 01 00 0A 00 01 00
        0B 00 01 00 0C 00 01 00  0D 00 01 00 0E 00 01 00
        0F 00 01 00 10 00 01 00  11 00 01 00 12 00 01 00
        13 00 01 00 14 00 01 00  15 00 01 00 16 00 01 00
        17 00 01 00 18 00 01 00  19 00 01 00 1A 00 01 00
        1B 00 01 00 1C 00 01 00  1D 00 01 00 1E 00 01 00
        1F 00 01 00 20 00 01 00  21 00 02 00 01 00 02 00
        02 00 02 00 03 00 02 00  04 00 02 00 06 00 02 00
        07 00 02 00 08 00 02 00  0A 00 02 00 0C 00 02 00
        0D 00 02 00 0E 00 02 00  0F 00 02 00 10 00 02 00
        11 00 02 00 12 00 02 00  13 00 02 00 14 00 02 00
        15 00 03 00 01 00 03 00  02 00 03 00 03 00 03 00
        06 00 03 00 07 00 03 00  08 00 03 00 09 00 03 00
        0A 00 03 00 0B 00 03 00  0C 00 04 00 01 00 04 00
        02 00 04 00 03 00 04 00  04 00 04 00 05 00 04 00
        07 00 04 00 08 00 04 00  09 00 04 00 0A 00 04 00
        0B 00 04 00 0C 00 04 00  0D 00 04 00 0E 00 04 00
        0F 00 04 00 10 00 04 00  11 00 04 00 12 00 04 00
        13 00 04 00 14 00 06 00  01 00 06 00 02 00 06 00
        03 00 08 00 01 00 08 00  02 00 09 00 01 00 09 00
        02 00 09 00 03 00 09 00  04 00 09 00 09 00 09 00
        0A 00 09 00 0B 00 0A 00  01 00 0A 00 02 00 0A 00
        03 00 0B 00 01 00 0B 00  02 00 0B 00 03 00 0B 00
        04 00 0C 00 01 00 0C 00  02 00 0C 00 03 00 13 00
        01 00 13 00 02 00 13 00  03 00 13 00 04 00 13 00
        05 00 13 00 06 00 13 00  07 00 13 00 08 00 13 00
        09 00 13 00 0A 00 13 00  0B 00 13 00 0C 00 13 00
        0D 00 13 00 0E 00 13 00  0F 00 13 00 10 00 13 00
        11 00 13 00 12 00 13 00  13 00 13 00 14 00 13 00
        15 00 13 00 16 00 13 00  17 00 13 00 18 00 13 00
        19 00 13 00 1A 00 13 00  1B 00 13 00 1C 00 13 00
        1D 00 13 00 1E 00 13 00  1F 00 13 00 20 00 13 00
        21 00 13 00 22 00 13 00  23 00 13 00 24 00 13 00
        25 00 13 00 26 00 13 00  27 00 13 00 28 00 15 00
        01 00 15 00 02 00 15 00  03 00 02 00 06 00 03 00
        04 00 03 00 05 00 09 00  05 00 09 00 06 00 09 00
        07 00 09 00 08 00 03 00  02 00 02 00 05 00 04 00
        06 00 04 00 02 00 02 00  09 00 02 00 0B 00 05 00
        00
        """
        cleaned_hex = (hex
                       .strip()
                       .replace(" ", "")
                       .replace("\r\n", "\n")
                       .replace("\n", ""))

        response_msg = SNACMessage(0x0001, 0x0007, 0x0000, 0x0000, bytes.fromhex(cleaned_hex))

        self.logger.info('<<< OSERVICE__RATE_PARAMS_REPLY')
        client.send_snac(response_msg)

    @Subgroup(0x0008)
    def rate_params_sub_add(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> OSERVICE__RATE_PARAMS_SUB_ADD (not implemented)')

        # since i don't have rate limits properly implemented *yet*, i won't do anything here

    @Subgroup(0x000E)
    def user_info_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> OSERVICE__USER_INFO_QUERY')

        self.logger.info('>>> Client screen name:', context.bs.user.username)
        self.logger.info('>>> Client IP:', client.get_ip())

        response_msg = SNACMessage(0x0001, 0x000F)
        response_msg.write_string_u8(context.bs.user.username)  # Screen name
        response_msg.write_u16(0)                               # Warning level

        date_created = context.bs.user.date_created
        date_login = context.bs.user.date_login

        date_created_unix = int(time.mktime(date_created.timetuple()))
        date_login_unix = int(time.mktime(date_login.timetuple()))

        response_msg.write_tlv_block([
            TLV(0x0001, struct.pack('>L', 0x0010)),             # User class (0x0010 = OSERVICE__USER_FLAG_OSCAR_FREE)
            TLV(0x0003, struct.pack('>L', date_login_unix)),    # Account signon time (unix time_t)
            TLV(0x0005, struct.pack('>L', date_created_unix)),  # Accout creation time (unix time_t)
            TLV(0x000A, client.get_ip()),                       # Client external IP
            TLV(0x000F, struct.pack('>L', 0))                   # Session length
        ])

        self.logger.info('<<< OSERVICE__USER_INFO_UPDATE')
        client.send_snac(response_msg)

    @Subgroup(0x0011)
    def idle_notification(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info('>>> OSERVICE__IDLE_NOTIFICATION')

        idle_time = message.read_u32()
        if idle_time == 0:
            self.logger.info(context.bs.user.username, 'is no longer idle')
        else:
            self.logger.info(context.bs.user.username, 'has been idle for', str(idle_time), 'seconds')

    @Subgroup(0x0002)
    def client_online(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info('>>> OSERVICE__CLIENT_ONLINE (not implemented)')
        self.logger.info(message.data.hex())

    @Subgroup(0x0004)
    def service_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info('>>> OSERVICE__SERVICE_REQUEST (not implemented)')
        self.logger.info(message.data.hex())
