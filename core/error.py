class ClientError(Exception):
	pass

class ServerError(Exception):
	pass

class GroupNameTooLong(ClientError):
	pass

class GroupDoesNotExist(ClientError):
	pass

class GroupAlreadyExists(ClientError):
	pass

class CannotRemoveSpecialGroup(ClientError):
	pass

class ContactDoesNotExist(ClientError):
	pass

class ContactAlreadyOnList(ClientError):
	pass

class NicknameExceedsLengthLimit(ClientError):
	pass

class SpecialMessageNotSentWithDType(ClientError):
	pass

class EmptyDomainInXXL(ClientError):
	pass

class InvalidXXLPayload(ClientError):
	pass

class ContactNotOnList(ClientError):
	pass

class UserDoesNotExist(ClientError):
	pass

class ContactNotOnline(ClientError):
	pass

class AuthFail(ClientError):
	pass

class NotAllowedWhileHDN(ClientError):
	pass

class NotAllowedToJoinGroupChat(ClientError):
	pass

class MemberDoesntHaveSufficientGroupChatRole(ClientError):
	pass

class GroupChatDoesNotExist(ClientError):
	pass

class MemberAlreadyInGroupChat(ClientError):
	pass

class MemberAlreadyInvitedToGroupChat(ClientError):
	pass

class GroupChatMemberIsPending(ClientError):
	pass

class CantLeaveGroupChat(ClientError):
	pass

class MemberNotInGroupChat(ClientError):
	pass

class ListIsFull(ClientError):
	pass

class DataTooLargeToSend(ServerError):
	pass
