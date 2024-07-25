from ..misc import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from util.misc import Logger


@Foodgroup(0x0002)
class LocateFoodgroup:
    logger: Logger

    @Subgroup(0x0002)
    def client_versions(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> LOCATE__RIGHTS_QUERY')

        # TODO(subpurple): implement
