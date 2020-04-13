from typing import TYPE_CHECKING, Optional, Dict, Any, List
from abc import ABCMeta, abstractmethod

from .models import User, Contact, OIM, GroupChat, GroupChatRole, MessageData, TextWithData, Substatus, LoginOption
from util.misc import MultiDict

if TYPE_CHECKING:
	from .backend import BackendSession, Chat, ChatSession

class BackendEventHandler(metaclass = ABCMeta):
	__slots__ = ('bs',)
	
	bs: 'BackendSession'
	
	# Note to subclassers, regarding `__init__`:
	# `bs` is assigned in `Backend.login`, before `BackendEventHandler.on_open` is called,
	# because of circular references.
	# Therefore, your `__init__` should be conspicuously missing an assignment to `bs`.
	
	def on_open(self) -> None:
		pass
	
	def on_close(self) -> None:
		pass
	
	def on_system_message(self, *args: Any, **kwargs: Any) -> None:
		pass
	
	def on_maintenance_boot(self) -> None:
		pass
	
	@abstractmethod
	def on_presence_notification(
		self, ctc: Contact, on_contact_add: bool, old_substatus: Substatus, *,
		trid: Optional[str] = None, update_status: bool = True, update_info_other: bool = True,
		send_status_on_bl: bool = False, sess_id: Optional[int] = None, updated_phone_info: Optional[Dict[str, Any]] = None,
	) -> None: pass
	
	@abstractmethod
	def on_presence_self_notification(self, old_substatus: Substatus, *, update_status: bool = True, update_info: bool = True) -> None: pass
	
	@abstractmethod
	def on_chat_invite(
		self, chat: 'Chat', inviter: User, *,
		group_chat: bool = False, inviter_id: Optional[str] = None, invite_msg: str = '',
	) -> None: pass
	
	@abstractmethod
	def on_declined_chat_invite(self, chat: 'Chat', group_chat: bool = False) -> None: pass
	
	# `user` added me to their FL, and they're now on my RL.
	@abstractmethod
	def on_added_me(self, user: User, *, adder_id: Optional[str] = None, message: Optional[TextWithData] = None) -> None: pass
	
	@abstractmethod
	def on_removed_me(self, user: User) -> None: pass
	
	# `user` didn't accept contact request
	@abstractmethod
	def on_contact_request_denied(self, user_added: User, message: str, *, contact_id: Optional[str] = None) -> None: pass
	
	@abstractmethod
	def on_login_elsewhere(self, option: LoginOption) -> None: pass
	
	@abstractmethod
	def on_oim_sent(self, oim: OIM) -> None: pass
	
	@abstractmethod
	def on_groupchat_created(self, groupchat: GroupChat) -> None: pass
	
	@abstractmethod
	def on_groupchat_invite_revoked(self, chat_id: str) -> None: pass
	
	@abstractmethod
	def on_accepted_groupchat_invite(self, groupchat: GroupChat) -> None: pass
	
	@abstractmethod
	def on_groupchat_updated(self, groupchat: GroupChat) -> None: pass
	
	@abstractmethod
	def on_left_groupchat(self, groupchat: GroupChat) -> None: pass
	
	@abstractmethod
	def on_groupchat_role_updated(self, chat_id: str, role: GroupChatRole) -> None: pass
	
	# TODO: Make these non-frontend-specific to allow interop
	
	def msn_on_oim_deletion(self, oims_deleted: int) -> None:
		pass
	
	def msn_on_uun_sent(
		self, sender: User, type: int, data: Optional[bytes], *,
		pop_id_sender: Optional[str] = None, pop_id: Optional[str] = None,
	) -> None:
		pass
	
	def msn_on_notify_ab(self) -> None:
		pass
	
	def msn_on_notify_circle_ab(self, chat_id: str) -> None:
		pass
	
	def ymsg_on_p2p_msg_request(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_xfer_init(self, sess_id: int, yahoo_data: MultiDict[bytes, bytes]) -> None:
		pass
	
	def ymsg_on_sent_ft_http(self, yahoo_id_sender: str, url_path: str, upload_time: float, message: str) -> None:
		pass
	
	def ymsg_on_upload_file_ft(self, recipient: str, message: str) -> None:
		pass

class ChatEventHandler(metaclass = ABCMeta):
	__slots__ = ('cs',)
	
	cs: 'ChatSession'
	
	# Note to subclassers, regarding `__init__`:
	# `cs` is assigned in `Chat.join`, before `ChatEventHandler.on_open` is called,
	# because of circular references.
	# Therefore, your `__init__` should be conspicuously missing an assignment to `cs`.
	
	def on_open(self) -> None:
		pass
	
	def on_close(self) -> None:
		pass
	
	@abstractmethod
	def on_participant_joined(self, cs_other: 'ChatSession', first_pop: bool, initial_join: bool) -> None: pass
	
	@abstractmethod
	def on_participant_left(self, cs_other: 'ChatSession', last_pop: bool) -> None: pass
	
	@abstractmethod
	def on_chat_invite_declined(
		self, chat: 'Chat', invitee: User, *,
		invitee_id: Optional[str] = None, message: Optional[str] = None, group_chat: bool = False,
	) -> None: pass
	
	@abstractmethod
	def on_chat_updated(self) -> None: pass
	
	@abstractmethod
	def on_chat_roster_updated(self) -> None: pass
	
	@abstractmethod
	def on_participant_status_updated(self, cs_other: 'ChatSession', first_pop: bool, initial: bool, old_substatus: Substatus) -> None: pass
	
	@abstractmethod
	def on_message(self, data: MessageData) -> None: pass
