from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from util.misc import Logger


@Foodgroup(0x0003)
class BuddyFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info(">>> BUDDY__RIGHTS_QUERY (not implemented)")
