from ..misc import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from util.misc import Logger


@Foodgroup(0x0004)
class ICBMFoodgroup:
    logger: Logger

    @Subgroup(0x0004)
    def parameter_query(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> ICBM__PARAMENTER_QUERY')

        # TODO(subpurple): implement
