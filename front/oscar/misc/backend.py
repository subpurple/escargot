from core import event
from core.backend import BackendSession, Chat
from core.models import Contact, Substatus, GroupChat, GroupChatRole, User, TextWithData, OIM, LoginOption
from typing import Optional, Any, Dict


class BackendEventHandler(event.BackendEventHandler):
    __slots__ = ('ctrl', 'bs')

    ctrl: Any
    bs: Optional[BackendSession]

    def __init__(self, ctrl: Any) -> None:
        self.ctrl = ctrl
        self.bs = None

    def on_system_message(self, *args: Any, message: str = '', **kwargs: Any) -> None:
        self.ctrl.logger.info('on_system_message')
        pass

    def on_maintenance_boot(self) -> None:
        self.ctrl.logger.info('on_maintenance_boot')
        pass

    def on_presence_notification(
            self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
            trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
            send_status_on_bl: bool = False, sess_id: Optional[int] = None,
            updated_phone_info: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.ctrl.logger.info('on_presence_notification')
        pass

    def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True,
                                      update_info: bool = True) -> None:
        self.ctrl.logger.info('on_presence_self_notification')
        pass

    def on_groupchat_created(self, groupchat: GroupChat) -> None:
        self.ctrl.logger.info('on_groupchat_created')
        pass

    def on_groupchat_updated(self, groupchat: GroupChat) -> None:
        self.ctrl.logger.info('on_groupchat_updated')
        pass

    def on_left_groupchat(self, groupchat: GroupChat) -> None:
        self.ctrl.logger.info('on_left_groupchat')
        pass

    def on_accepted_groupchat_invite(self, groupchat: GroupChat) -> None:
        self.ctrl.logger.info('on_accepted_groupchat_invite')
        pass

    def on_groupchat_invite_revoked(self, chat_id: str) -> None:
        self.ctrl.logger.info('on_groupchat_invite_revoked')
        pass

    def on_groupchat_role_updated(self, chat_id: str, role: GroupChatRole) -> None:
        self.ctrl.logger.info('on_groupchat_role_updated')
        pass

    def on_chat_invite(
            self, chat: Chat, inviter: User, *, group_chat: bool = False, inviter_id: Optional[str] = None,
            invite_msg: str = '',
    ) -> None:
        self.ctrl.logger.info('on_chat_invite')
        pass

    def on_declined_chat_invite(self, chat: Chat, group_chat: bool = False) -> None:
        self.ctrl.logger.info('on_declined_chat_invite')
        pass

    def on_added_me(self, user: User, *, adder_id: Optional[str] = None,
                    message: Optional[TextWithData] = None) -> None:
        self.ctrl.logger.info('on_added_me')
        pass

    def on_removed_me(self, user: User) -> None:
        self.ctrl.logger.info('on_removed_me')
        pass

    def on_contact_request_denied(self, user_added: User, message: Optional[str], *,
                                  contact_id: Optional[str] = None) -> None:
        self.ctrl.logger.info('on_contact_request_denied')
        pass

    def on_oim_sent(self, oim: OIM) -> None:
        self.ctrl.logger.info('on_oim_sent')
        pass

    def on_login_elsewhere(self, option: LoginOption) -> None:
        self.ctrl.logger.info('on_login_elsewhere')
        pass

    def on_close(self) -> None:
        self.ctrl.close()
