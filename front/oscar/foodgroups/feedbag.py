from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from util.misc import Logger


@Foodgroup(0x0013)
class FeedbagFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def rights_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info(">>> FEEDBAG__RIGHTS_QUERY (not implemented)")

    @Subgroup(0x0005)
    def query_if_modified(self, client: OSCARClient, context: OSCARContext, message: SNACMessage):
        self.logger.info('>>> FEEDBAG__QUERY_IF_MODIFIED (not implemented)')
