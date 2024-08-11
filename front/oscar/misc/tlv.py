import struct

from dataclasses import dataclass
from typing import Optional


@dataclass
class TLV:
    __slots__ = ('type', 'data')

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


def marshal_tlvs(tlvs: list[TLV]) -> bytes:
    return b''.join([tlv.marshal() for tlv in tlvs])


def unmarshal_tlvs(data: bytes) -> list[TLV]:
    tlvs = []

    while len(data) > 4:
        type, length = struct.unpack('>HH', data[0:4])

        # make sure length is not too long
        assert len(data) > length - 4

        value = data[4:length + 4]

        tlvs.append(TLV(type, value))
        data = data[length + 4:]

    return tlvs


def find_tlv(tlvs: list[TLV], type: int) -> Optional[TLV]:
    for tlv in tlvs:
        if tlv.type == type:
            return tlv

    return None
