import asyncio
import struct
import front.oscar.ctrl as ctrl

from array import array
from dataclasses import dataclass
from typing import Optional, Callable, Any

foodgroups = {}


@dataclass
class TLV:
    type: int
    data: bytes

    def __init__(self, type: int, data: bytes | str):
        self.type = type

        if isinstance(data, str):
            self.data = data.encode()
        else:
            self.data = data

    def marshal(self) -> bytes:
        return b''.join([
            struct.pack('>HH', self.type, len(self.data)),
            self.data
        ])


@dataclass
class SNACMessage:
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

    def add_tlv(self, tlv: TLV) -> None:
        self.data += tlv.marshal()

    def add_tlvs(self, tlvs: array[TLV]) -> None:
        self.data += encode_tlvs(tlvs)

    def add_bytes(self, value: bytes) -> None:
        self.data += value

    def add_u16(self, value) -> None:
        self.data += struct.pack('>H', value)

    def add_u32(self, value) -> None:
        self.data += struct.pack('>L', value)


class OSCARClient:
    # Any because of circular imports
    # TODO(subpurple): make this less hacky
    def __init__(self, ctrl: Any) -> None:
        self.ctrl = ctrl

    def send_snac(self, msg: SNACMessage) -> None:
        self.ctrl.send_specific_frame(0x02, msg.marshal())


class OSCARContext:
    pass


class Foodgroup:
    value: int

    def __init__(self, value):
        self.value = value

    def __call__(self, *args):
        self.cls = args[0]

        instance = self.cls()
        foodgroups[self.value] = instance


class Subgroup:
    value: int
    mode: str
    func: Callable

    def __init__(self, value):
        self.value = value
        self.mode = 'decorating'

    def __call__(self, *args):
        if self.mode == 'decorating':
            self.func = args[0]
            self.mode = 'calling'
            return self

        return self.func(*args)

    def __set_name__(self, owner, name):
        if not hasattr(owner, 'subgroups'):
            owner.subgroups = {}

        owner.subgroups[self.value] = self.func

        self.func.class_name = owner.__name__
        setattr(owner, name, self.func)


def encode_tlvs(tlvs: list[TLV]) -> bytes:
    return b''.join([tlv.marshal() for tlv in tlvs])


def decode_tlvs(data: bytes) -> list[TLV]:
    tlvs = []

    while len(data) > 4:
        type, length = struct.unpack('>HH', data[0:4])
        value = data[4:length + 4]

        tlvs.append(TLV(type, value))
        data = data[length + 4:]

    return tlvs


def find_tlv(tlvs: list[TLV], type: int):
    for tlv in tlvs:
        if tlv.type == type:
            return tlv

    return None
