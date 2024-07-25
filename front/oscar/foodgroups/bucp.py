import os
import random
import string
import struct
import settings

from ..misc import OSCARClient, OSCARContext, SNACMessage, Foodgroup, Subgroup, TLV, decode_tlvs, find_tlv
from util.misc import Logger
from urllib.parse import quote

authorize = True


# TODO(subpurple): add logger to foodgroup class
@Foodgroup(0x0017)
class BUCPFoodgroup:
    logger: Logger

    @Subgroup(0x0006)
    def challenge_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BUCP__CHALLENGE_REQUEST')

        key = ''.join(random.choices(string.digits, k=10))

        response = SNACMessage(0x0001, 0x0007)
        response.add_u16(len(key))
        response.add_bytes(key.encode())

        self.logger.info('<<< BUCP__CHALLENGE_RESPONSE (key:', key + ')')
        client.send_snac(response)

    @Subgroup(0x0002)
    def login_request(self, client: OSCARClient, context: OSCARContext, message: SNACMessage) -> None:
        self.logger.info('>>> BUCP__LOGIN_REQUEST')

        tlvs = decode_tlvs(message.data)

        screen_name_tlv = find_tlv(tlvs, 0x0001)
        hashed_pw_tlv = find_tlv(tlvs, 0x0025)

        screen_name = screen_name_tlv.data.decode()

        print('>>> Screen Name:', screen_name)
        print('>>> Password (hashed):', hashed_pw_tlv.data)

        email = f'{screen_name}@aol.com'
        password_change_url = f'http://aim.aol.com/redirects/password/change_password.adp?ScreenName={quote(screen_name)}&ccode=us&lang=en'

        response_msg = SNACMessage(0x0017, 0x0003)

        # TODO(subpurple): actually authorize the user
        global authorize

        if authorize:
            print('<<< BUCP__LOGIN_RESPONSE (authorized)')

            response_msg.add_tlvs([
                TLV(0x0005, f'{settings.TARGET_HOST}:5190'),  # BOS address
                TLV(0x0006, os.urandom(256)),  # BOS authorization cookie
                TLV(0x0011, email),  # User's e-mail address
                TLV(0x0013, struct.pack('>H', 1)),  # Registration status
                TLV(0x0054, password_change_url),  # Password change URL
                TLV(0x008E, b'\0'),  # Unknown
                TLV(0x0001, screen_name)  # Screen name
            ])
        else:
            print('<<< BUCP__LOGIN_RESPONSE (unauthorized)')

            error_code = 0x0001  # 0x0001 = Unregistered Screenname, 0x0005 = Mismatched Password
            error_url = \
                "http://www.aim.aol.com/errors/UNREGISTERED_SCREENNAME.html" \
                    if error_code == 0x0001 \
                    else "http://www.aim.aol.com/errors/MISMATCH_PASSWD.html"

            response_msg.add_tlvs([
                TLV(0x0008, struct.pack('>H', error_code)),
                TLV(0x0004, error_url),
                TLV(0x0001, screen_name)
            ])

        client.send_snac(response_msg)
