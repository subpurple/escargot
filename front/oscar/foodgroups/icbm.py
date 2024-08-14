from util.misc import Logger

from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup


@Foodgroup(0x0004)
class ICBMFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def add_paramenters(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> ICBM__ADD_PARAMENTERS (not implemented)')
        self.logger.info('>>>', message.data.hex())

    @Subgroup(0x0004)
    def parameter_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> ICBM__PARAMENTER_QUERY')

        response_msg = SNACMessage(0x0004, 0x0005)

        # Response from NINA's servers:
        # ==
        # 0000   2a 02 00 0a 00 1a 00 04 00 05 00 00 00 00 00 04   *...............
        #        [FLAP Header....] [SNAC Header................]
        # 0010   00 05 00 00 00 03 02 00 03 84 03 e7 00 00 03 e8   ................
        #
        # The response data are not TLVs and are instead WORD/DWORDs so I cannot fit
        # the names below the hex data.  See https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/ICBM_PARAMETER_REPLY and
        # https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/ICBM_ADD_PARAMETERS for more information.
        response_msg.write_u16(5)         # maxSlots
        response_msg.write_u32(0x00003)   # icbmFlags (default)
        response_msg.write_u16(512)       # maxIncomingICBMLen
        response_msg.write_u16(999)       # maxSourceEvil
        response_msg.write_u16(999)       # maxDestinationEvil
        response_msg.write_u32(1000)      # minInterICBMInterval

        self.logger.info('<<< ICBM__PARAMENTER_REPLY')
        client.send_snac(response_msg)

