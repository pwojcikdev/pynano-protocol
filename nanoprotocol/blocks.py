import binascii
from dataclasses import dataclass
from enum import Enum
from io import BufferedIOBase
from os import access
from typing import ClassVar, Protocol

from . import common


class BlockType(Enum):
    INVALID = 0
    NOT_A_BLOCK = 1
    SEND = 2
    RECEIVE = 3
    OPEN = 4
    CHANGE = 5
    STATE = 6


class BlockPayload(Protocol):
    SIZE: int

    def serialize(self, stream: BufferedIOBase):
        pass

    def deserialize(self, stream: BufferedIOBase):
        pass

    def from_dict(self, data: dict):
        pass


block_name_mapping: dict[str, BlockType] = {
    "send": BlockType.SEND,
    "receive": BlockType.RECEIVE,
    "open": BlockType.OPEN,
    "change": BlockType.CHANGE,
    "state": BlockType.STATE,
}


def block_name_to_type(name: str) -> BlockType:
    return block_name_mapping[name]


block_mapping: dict[BlockType, type[BlockPayload]]


def create_block_by_type(type: BlockType) -> BlockPayload:
    return block_mapping[type]()


@dataclass(init=False)
class BlockWrapper:
    type: BlockType
    payload: BlockPayload

    signature: bytes  # 64 bytes
    work: bytes  # 8 bytes

    # signature + work
    PARTIAL_SIZE: ClassVar[int] = 64 + 8

    def serialize(self, stream: BufferedIOBase):
        self.payload.serialize(stream)
        stream.write(self.signature)
        # stream.write(self.work.to_bytes(8, "big"))
        stream.write(self.work)

    def deserialize(self, stream: BufferedIOBase):
        self.payload = create_block_by_type(self.type)
        self.payload.deserialize(stream)
        self.signature = stream.read(64)
        # self.work = int.from_bytes(8, "big")
        self.work = stream.read(8)

    def size(self) -> int:
        return self.block_size(self.type)

    @staticmethod
    def block_size(type: BlockType) -> int:
        return BlockWrapper.PARTIAL_SIZE + block_mapping[type].SIZE

    def from_dict(self, data: dict):
        self.type = block_name_to_type(data["type"])
        self.payload = create_block_by_type(self.type)
        self.payload.from_dict(data)
        self.signature = binascii.unhexlify(data["signature"])
        self.work = binascii.unhexlify(data["work"])


def block_from_dict(data: dict) -> BlockWrapper:
    block = BlockWrapper()
    block.from_dict(data)
    return block


@dataclass(init=False)
class BlockSend:
    SIZE: ClassVar = 80

    def serialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    def deserialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    pass


@dataclass(init=False)
class BlockReceive:
    SIZE: ClassVar = 64

    def serialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    def deserialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    pass


@dataclass(init=False)
class BlockOpen:
    SIZE: ClassVar = 96

    def serialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    def deserialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    pass


@dataclass(init=False)
class BlockChange:
    SIZE: ClassVar = 136

    def serialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    def deserialize(self, stream: BufferedIOBase):
        raise NotImplementedError()
        pass

    pass


@dataclass(init=False)
class BlockState:
    account: bytes  # 32 bytes
    previous: bytes  # 32 bytes
    representative: bytes  # 32 bytes
    balance: int  # 16 bytes
    link: bytes  # 32 bytes

    # account + previous + representative + balance + link
    SIZE: ClassVar = 144

    def serialize(self, stream: BufferedIOBase):
        assert len(self.account) == 32
        assert len(self.previous) == 32
        assert len(self.representative) == 32
        assert len(self.link) == 32

        stream.write(self.account)
        stream.write(self.previous)
        stream.write(self.representative)
        stream.write(self.balance.to_bytes(16, "big"))
        stream.write(self.link)

    def deserialize(self, stream: BufferedIOBase):
        self.account = stream.read(32)
        self.previous = stream.read(32)
        self.representative = stream.read(32)
        self.balance = int.from_bytes(stream.read(16), "big")
        self.link = stream.read(32)

    def from_dict(self, data: dict):
        assert data["type"] == "state"
        # account is "nano_(...)" str
        self.account = binascii.unhexlify(common.hexify_account(data["account"]))
        self.previous = binascii.unhexlify(data["previous"])
        # rep is "nano_(...)" str
        self.representative = binascii.unhexlify(common.hexify_account(data["representative"]))
        self.balance = int(data["balance"])
        self.link = binascii.unhexlify(data["link"])


block_mapping = {
    BlockType.SEND: BlockSend,
    BlockType.RECEIVE: BlockReceive,
    BlockType.OPEN: BlockOpen,
    BlockType.CHANGE: BlockChange,
    BlockType.STATE: BlockState,
}
