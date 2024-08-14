import struct

from util.misc import Logger

from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..misc.tlv import TLV


@Foodgroup(0x0003)
class BuddyFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BUDDY_RIGHTS_QUERY')

        response_msg = SNACMessage(0x0003, 0x0003)
        response_msg.write_tlvs([
            TLV(0x0001, struct.pack('>H', 1000)),  # max buddies
            TLV(0x0002, struct.pack('>H', 3000)),  # max watchers
            TLV(0x0004, struct.pack('>H', 160))    # max temp buddies
        ])

        self.logger.info('<<< BUDDY_RIGHTS_REPLY')
        client.send_snac(response_msg)
