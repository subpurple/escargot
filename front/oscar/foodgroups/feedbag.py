import struct

from array import array
from dataclasses import dataclass
from enum import IntEnum
from util.misc import Logger

from ..misc.tlv import TLV, marshal_tlvs
from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup


# I only put the classes I need in this IntEnum
#
# For a complete list of feedbag classes, see https://wiki.nina.chat/wiki/Protocols/OSCAR/Foodgroups/FEEDBAG/Items#Class:_FEEDBAG_CLASS_IDS
class FeedbagClass(IntEnum):
    Buddy = 0x0000,
    Group = 0x0001


@dataclass
class FeedbagItem:
    name: str
    group_id: int
    item_id: int
    class_id: int
    attributes: array[TLV]

    def __init__(self, name: str, group_id: int, item_id: int, class_id: int, attributes: array[TLV]) -> None:
        self.name = name
        self.group_id = group_id
        self.item_id = item_id
        self.class_id = class_id
        self.attributes = attributes

    def marshal(self) -> bytes:
        marshalled_attributes = marshal_tlvs(self.attributes)

        return b''.join([
            struct.pack('>H', len(self.name)),
            self.name.encode(),

            struct.pack('>HHHH', self.group_id, self.item_id, self.class_id, len(marshalled_attributes)),
            marshalled_attributes
        ])


@Foodgroup(0x0013)
class FeedbagFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> FEEDBAG__RIGHTS_QUERY')

        response_msg = SNACMessage(0x0013, 0x0003)

        # https://wiki.nina.chat/wiki/Protocols/OSCAR/SNAC/FEEDBAG_RIGHTS_REPLY#TLV_Class:_FEEDBAG_RIGHTS_REPLY_TAGS
        response_msg.write_tlvs([
            TLV(0x0002, struct.pack('>H', 254)),    # max class attrs
            TLV(0x0003, struct.pack('>H', 1698)),   # max item attrs

            # Maximum Items
            # ==
            # 0000   03 e8 00 64 03 e8 03 e8 00 01 00 01 00 96 00 0c   ...d............
            #        ...............................................
            # 0010   00 0c 00 03 00 32 00 32 00 00 00 80 03 e8 00 14   .....2.2........
            #        ...............................................
            # 0020   00 c8 00 01 00 64 00 01 00 19 00 01 00 28 00 01   .....d.......(..
            #        .............................
            # 0030   00 0a 00 c8 00 01 00 3c 00 c8 00 01 00 08 00 14   .......<........
            # 0040   00 01 27 10 03 e8 03 e8 00 32 00 01 00 05 01 f4   ..'......2......
            # 0050   00 01 00 08 27 10 00 01 00 01 00 01 27 10 00 00   ....'.......'...
            # 0060   00 00 00 01 07 d0 00 00 00 3c 00 18 00 0a 00 01   .........<......
            # 0070   00 00 00 00 00 00 00 00 00 01 00 01 00 01 00 01   ................
            # 0080   03 e8 00 01 00 01                                 ......
            #
            #   03 e8 - max num of contacts (1000)              [1]
            #   00 64 - max num of groups (100)                 [2]
            #   03 e8 - max num of visible contacts (1000)      [3]
            #   03 e8 - max num of invisible contacts (1000)    [4]
            #   00 01 - max vis/invis bitmasks (1)              [5]
            #   00 01 - max presence info fields (1)            [6]
            #   00 96 - limit for item type 06 (150)            [7]
            #   00 0c - limit for item type 07 (12)             [8]
            #   00 0c - limit for item type 08 (12)             [9]
            #   00 03 - limit for item type 09 (3)              [10]
            #   00 32 - limit for item type 0a (50)             [11]
            #   00 32 - limit for item type 0b (50)             [12]
            #   00 00 - limit for item type 0c (0)              [13]
            #   00 80 - limit for item type 0d (128)            [14]
            #   03 e8 - max ignore list entries (1000)          [15]
            #   00 14 - limit for item type 0f (20)             [16]
            #   00 c8 - limit for item 10 (200)                 [17]
            #   00 01 - limit for item 11 (1)                   [18]
            #   00 64 - limit for item 12 (100)                 [19]
            #   00 01 - limit for item 13 (1)                   [20]
            #   00 19 - limit for item 14 (25)                  [21]
            #
            #   xx xx - unknown (possibly more limits?)
            #           NINA does not even say *anything* about the values inside the maximum items TLV,
            #           Shutko does - but he only goes into the 20 values seen above
            TLV(0x0004, struct.pack(f'>{'H' * 67}',
                                    1000,       # max num of contacts
                                    100,        # max num of groups
                                    1000,       # max num of visible contacts
                                    1000,       # max num of invisible contacts
                                    1,          # max vis/invis bitmasks
                                    1,          # max presence info fields
                                    150,        # limit for item type 06
                                    12,         # limit for item type 07
                                    12,         # limit for item type 08
                                    3,          # limit for item type 09
                                    50,         # limit for item type 0a
                                    50,         # limit for item type 0b
                                    0,          # limit for item type 0c
                                    128,        # limit for item type 0d
                                    1000,       # max ignore list entries
                                    20,         # limit for item type 0f
                                    200,        # limit for item 10
                                    1,          # limit for item 11
                                    100,        # limit for item 12
                                    1,          # limit for item 13
                                    25,         # limit for item 14

                                    # These values are unknown but are here in the sake of keeping response
                                    # parity with NINA:
                                    1, 40, 1, 10, 200, 1, 60, 200, 1, 8, 20, 1, 10000, 1000, 1000, 50, 1, 5,
                                    500,
                                    1, 8, 10000, 1, 1, 1,
                                    10000, 0, 0, 1, 2000, 0, 60, 24, 10, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1000, 1,
                                    1)),

            TLV(0x0005, struct.pack('>H', 100)),        # max client items
            TLV(0x0006, struct.pack('>H', 97)),         # max item name len
            TLV(0x0007, struct.pack('>H', 2000)),       # max recent buddies
            TLV(0x0008, struct.pack('>H', 10)),         # interaction buddies
            TLV(0x0009, struct.pack('>L', 432000)),     # interaction half life - in 2^(-age/half_life) in seconds
            TLV(0x000A, struct.pack('>L', 14)),         # interaction max score
            TLV(0x000B, struct.pack('>H', 0)),          # unknown
            TLV(0x000C, struct.pack('>H', 600)),        # max buddies per group
            TLV(0x000D, struct.pack('>H', 200)),        # max allowed bot buddies
            TLV(0x000E, struct.pack('>H', 32))          # max smart groups
        ])

        self.logger.info('<<< FEEDBAG__RIGHTS_REPLY')
        client.send_snac(response_msg)

    @Subgroup(0x0004)
    def query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> FEEDBAG__QUERY (not implemented)')

    @Subgroup(0x0005)
    def query_if_modified(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> FEEDBAG__QUERY_IF_MODIFIED (not implemented)')

        # 66 51 29 47 00 0D
        #
        #   66 51 29 47 - u32 for unix timestamp of cached client-side feedbag
        #   00 0D       - u16 for number of items in cached client-side feedbag
        cached_feedbag_timestamp = message.read_u32()
        cached_feedbag_num_items = message.read_u16()

        self.logger.info('>>> Cached feedbag timestamp:', cached_feedbag_timestamp)
        self.logger.info('>>> Cached feedbag items num:', cached_feedbag_num_items)

        # TODO(subpurple): do check
        self.query(client, context, message)

