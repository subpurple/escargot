import os
import struct
import settings

from ..misc.snac import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup
from ..misc.tlv import TLV, unmarshal_tlvs, find_tlv
from ..misc.backend import BackendEventHandler
from ..ctrl import bos_cookies
from core.models import LoginOption
from util.misc import Logger
from util.hash import gen_salt


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

        self.logger.info('>>> Screen Name:', screen_name)
        self.logger.info('>>> Password (hashed):', hashed_pw_tlv.data)

        response_msg = SNACMessage(0x0017, 0x0003)

        error_code, error_url = None, None

        if (uuid := context.backend.util_get_uuid_from_username(screen_name)) is None:
            error_code = 0x0001
            error_url = 'http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html'

            self.logger.info('>>> Unregistered screenname')
        elif not context.backend.user_service.aim_login_md5(screen_name, hashed_pw_tlv.data):
            error_code = 0x0005
            error_url = 'http://www.aim.aol.com/errors/MISMATCH_PASSWD.html'

            self.logger.info('>>> Incorrect password')

        if error_code is None:
            self.logger.info('>>>', screen_name, 'authorized successfully!')

            context.bs = context.backend.login(uuid,
                                               context.client,
                                               BackendEventHandler(self),
                                               option=LoginOption.NotifyOthers)
            context.user = context.bs.user

            bos_cookie = os.urandom(256)
            bos_cookies.append({bos_cookie: context})

            screen_name = context.user.username
            email = context.user.email

            self.logger.info('>>> Screen Name (normalized):', screen_name)
            self.logger.info('>>> E-mail:', email)

            self.logger.info('<<< BUCP__LOGIN_RESPONSE')

            response_msg.write_tlvs([
                TLV(0x0005, f'{settings.TARGET_HOST}:5190'),            # BOS address
                TLV(0x0006, bos_cookie),                                # BOS authorization cookie
                TLV(0x0011, email),                                     # User's e-mail address
                TLV(0x0013, struct.pack('>H', 1)),                      # Registration status
                TLV(0x0054, pw_change_url_format.format(screen_name)),  # Password change URL
                TLV(0x008E, b'\0')                                      # Unknown
            ])
        else:
            self.logger.info('<<< BUCP__LOGIN_RESPONSE')

            response_msg.write_tlvs([
                TLV(0x0008, struct.pack('>H', error_code)),  # Error code
                TLV(0x0004, error_url),                      # Error URL
            ])

        response_msg.write_tlv(TLV(0x0001, screen_name))

        client.send_snac(response_msg)
