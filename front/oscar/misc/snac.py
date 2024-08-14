import struct

from array import array
from core.backend import Backend, BackendSession
from core.client import Client
from core.models import User
from dataclasses import dataclass
from typing import Optional, Callable, Any

from .tlv import TLV, marshal_tlvs, unmarshal_tlvs

foodgroups = {}


@dataclass
class SNACMessage:
    __slots__ = ('foodgroup', 'subgroup', 'flags', 'request_id', 'data')

    foodgroup: int
    subgroup: int
    flags: int
    request_id: int
    data: bytes

    def __init__(self,
                 foodgroup: int = 0x0000,
                 subgroup: int = 0x0000,
                 flags: int = 0x0000,
                 request_id: int = 0x00000000,
                 data: bytes = b'') -> None:
        self.foodgroup = foodgroup
        self.subgroup = subgroup
        self.flags = flags
        self.request_id = request_id
        self.data = data

    def marshal(self) -> bytes:
        return b''.join([
            struct.pack('>HHHL', self.foodgroup, self.subgroup, self.flags, self.request_id),
            self.data
        ])

    def unmarshal(self, flap_data: bytes) -> None:
        self.foodgroup, self.subgroup, self.flags, self.request_id = struct.unpack('>HHHL', flap_data[:10])
        self.data = flap_data[10:]

    def read_u8(self) -> int:
        # read value
        value, = struct.unpack('>B', self.data[:1])

        # advance by 1 byte (size of u8)
        self.data = self.data[1:]

        # return read value
        return value

    def read_u16(self) -> int:
        # read value
        value, = struct.unpack('>H', self.data[:2])

        # advance by 2 bytes (size of u16)
        self.data = self.data[2:]

        # return read value
        return value

    def read_u32(self) -> int:
        # read value
        value, = struct.unpack('>L', self.data[:4])

        # advance by 4 bytes (size of u32)
        self.data = self.data[4:]

        # return read value
        return value

    def write_tlv(self, tlv: TLV) -> None:
        self.data += tlv.marshal()

    def write_tlvs(self, tlvs: array[TLV]) -> None:
        self.data += marshal_tlvs(tlvs)

    def write_tlv_block(self, tlvs: array[TLV]) -> None:
        self.write_u16(len(tlvs))
        self.write_tlvs(tlvs)

    def write_bytes(self, value: bytes) -> None:
        self.data += value

    def write_string(self, value: str) -> None:
        self.data += value.encode('utf-8')

    def write_string_u8(self, value: str) -> None:
        self.write_u8(len(value))
        self.write_string(value)

    def write_u8(self, value: int) -> None:
        self.data += struct.pack('>B', value)

    def write_u16(self, value: int) -> None:
        self.data += struct.pack('>H', value)

    def write_u32(self, value: int) -> None:
        self.data += struct.pack('>L', value)


class Foodgroup:
    __slots__ = ('value', 'cls')

    value: int
    cls: Any

    def __init__(self, value) -> None:
        self.value = value
        self.cls = None

    def __call__(self, *args) -> None:
        self.cls = args[0]

        foodgroups[self.value] = self.cls()


class Subgroup:
    __slots__ = ('value', 'mode', 'func')

    value: int
    mode: str
    func: Optional[Callable]

    def __init__(self, value) -> None:
        self.value = value
        self.mode = 'decorating'
        self.func = None

    def __call__(self, *args) -> Any:
        if self.mode == 'decorating':
            self.func = args[0]
            self.mode = 'calling'
            return self

        return self.func(*args)

    def __set_name__(self, owner, name) -> None:
        if not hasattr(owner, 'subgroups'):
            owner.subgroups = {}

        owner.subgroups[self.value] = self.func

        self.func.class_name = owner.__name__
        setattr(owner, name, self.func)


# OSCARClient and OSCARContext
class OSCARClient:
    __slots__ = 'ctrl'

    ctrl: Any  # Any because of circular imports - TODO(subpurple): make this less hacky

    def __init__(self, ctrl: Any) -> None:
        self.ctrl = ctrl

    def send_snac(self, msg: SNACMessage) -> None:
        self.ctrl.send_specific_frame(0x02, msg.marshal())

    def get_ip(self) -> str:
        ip, *_ = self.ctrl.transport.get_extra_info('peername')
        return ip


@dataclass
class OSCARContext:
    __slots__ = ('backend', 'bs', 'client', 'user')

    backend: Backend
    bs: Optional[BackendSession]
    client: Client

    # These slots are equivalent to .bs.* and only exist for the sake of convenience
    user: Optional[User]

    def __init__(self, backend: Backend, client: Client) -> None:
        self.backend = backend
        self.bs = None
        self.client = client
        self.user = None
