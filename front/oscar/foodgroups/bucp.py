from util.misc import Logger
from util.hash import gen_salt

from ..misc.backend import login
from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..misc.tlv import TLV, unmarshal_tlvs, find_tlv

pw_change_url_format = 'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={}&ccode=us&lang=en'


@Foodgroup(0x0017)
class BUCPFoodgroup:
    logger: Logger

    @Subgroup(0x0006)
    def challenge_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BUCP__CHALLENGE_REQUEST')

        tlvs = unmarshal_tlvs(message.data)
        screen_name_tlv = find_tlv(tlvs, 0x0001)
        screen_name = screen_name_tlv.data.decode()

        salt = context.backend.user_service.aim_get_md5_salt(screen_name)
        if salt is None:
            # screen name doesn't exist or user did not enable AIM
            salt = gen_salt()

        response = SNACMessage(0x0001, 0x0007)
        response.write_u16(len(salt))
        response.write_string(salt)

        self.logger.info('<<< BUCP__CHALLENGE_RESPONSE (salt:', salt + ')')
        client.send_snac(response)

    @Subgroup(0x0002)
    def login_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BUCP__LOGIN_REQUEST')

        tlvs = unmarshal_tlvs(message.data)

        screen_name_tlv = find_tlv(tlvs, 0x0001)
        hashed_pw_tlv = find_tlv(tlvs, 0x0025)

        screen_name = screen_name_tlv.data.decode()

        self.logger.info('Screen Name (client-given):', screen_name)
        self.logger.info('Password (hashed):', hashed_pw_tlv.data)

        response_msg = SNACMessage(0x0017, 0x0003)

        error_code = None

        if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
            error_code = 0x0001

            self.logger.info('Unregistered screenname')
        elif not context.backend.user_service.aim_login_md5(screen_name, hashed_pw_tlv.data):
            error_code = 0x0005
            self.logger.info('Incorrect password')

        response_msg.write_bytes(login(self.logger, context, tlvs, uuid, error_code))

        client.send_snac(response_msg)
