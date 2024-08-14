from util.misc import Logger

from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup

@Foodgroup(0x0009)
class BOSFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BOS__RIGHTS_QUERY (not implemented)')
