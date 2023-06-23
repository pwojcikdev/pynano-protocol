from dataclasses import dataclass
from distutils import extension
from email import header
from enum import Enum
from importlib.resources import is_resource
from inspect import signature
from io import BufferedIOBase, BytesIO
from operator import ne
from random import randbytes
from typing import ClassVar, Protocol
from urllib import response

from .blocks import BlockPayload, BlockType, BlockWrapper


class NetworkType(Enum):
    INVALID = 0x0
    # LOW WORK PARAMETERS, PUBLICLY KNOWN GENESIS KEY, DEV IP PORTS
    NANO_DEV_NETWORK = 0x5241  # 'R', 'A'
    # NORMAL WORK PARAMETERS, SECRET BETA GENESIS KEY, BETA IP PORTS
    NANO_BETA_NETWORK = 0x5242  # 'R', 'B'
    # NORMAL WORK PARAMETERS, SECRET LIVE KEY, LIVE IP PORTS
    NANO_LIVE_NETWORK = 0x5243  # 'R', 'C'
    # NORMAL WORK PARAMETERS, SECRET TEST GENESIS KEY, TEST IP PORTS
    NANO_TEST_NETWORK = 0x5258  # 'R', 'X'


@dataclass
class NetworkInfo:
    network: NetworkType
    version_max: int
    version_using: int
    version_min: int


NETWORK_NULL = NetworkInfo(
    network=NetworkType.INVALID,
    version_max=0,
    version_using=0,
    version_min=0,
)


NETWORK_TEST = NetworkInfo(
    network=NetworkType.NANO_TEST_NETWORK,
    version_max=0x13,
    version_using=0x13,
    version_min=0x12,
)

DEFAULT_NETWORK = NETWORK_TEST


class MessageType(Enum):
    INVALID = 0x0
    NOT_A_TYPE = 0x1
    KEEPALIVE = 0x2
    PUBLISH = 0x3
    CONFIRM_REQ = 0x4
    CONFIRM_ACK = 0x5
    BULK_PULL = 0x6
    BULK_PUSH = 0x7
    FRONTIER_REQ = 0x8
    # DELETED 0X9
    NODE_ID_HANDSHAKE = 0x0A
    BULK_PULL_ACCOUNT = 0x0B
    TELEMETRY_REQ = 0x0C
    TELEMETRY_ACK = 0x0D
    ASC_PULL_REQ = 0x0E
    ASC_PULL_ACK = 0x0F


@dataclass
class MessageHeader:
    @dataclass
    class Extensions:
        value: int

        def __init__(self, value: int):
            self.value = value

        def set(self, index: int, enabled=True):
            if enabled:
                self.value |= 1 << index
            else:
                self.value &= ~(1 << index)

        def test(self, index: int) -> bool:
            return (self.value & (1 << index)) != 0

    # PAYLOAD
    network: NetworkType
    version_max: int
    version_using: int
    version_min: int
    type: MessageType
    extensions: Extensions

    SIZE: ClassVar[int] = 8

    def __init__(
        self,
        type: MessageType = MessageType.INVALID,
        network: NetworkInfo = NETWORK_NULL,
    ):
        # network
        self.network = network.network
        self.version_max = network.version_max
        self.version_using = network.version_using
        self.version_min = network.version_min
        # message
        self.type = type
        self.extensions = MessageHeader.Extensions(0)

    def serialize(self, stream: BufferedIOBase):
        stream.write(self.network.value.to_bytes(2, "big"))
        stream.write(self.version_max.to_bytes(1, "big"))
        stream.write(self.version_using.to_bytes(1, "big"))
        stream.write(self.version_min.to_bytes(1, "big"))
        type_id = self.type.value
        stream.write(type_id.to_bytes(1, "big"))
        # TODO: bitset endianess
        # stream.write(self.extensions.value.to_bytes(2, "big"))
        stream.write(self.extensions.value.to_bytes(2, "little"))

    def deserialize(self, stream: BufferedIOBase):
        network_id = int.from_bytes(stream.read(2), "big")
        self.network = NetworkType(network_id)
        self.version_max = int.from_bytes(stream.read(1), "big")
        self.version_using = int.from_bytes(stream.read(1), "big")
        self.version_min = int.from_bytes(stream.read(1), "big")
        type_id = int.from_bytes(stream.read(1), "big")
        self.type = MessageType(type_id)
        # TODO: bitset endianess
        # extensions_value = int.from_bytes(stream.read(2), "big")
        extensions_value = int.from_bytes(stream.read(2), "little")
        self.extensions = MessageHeader.Extensions(extensions_value)


class MessagePayload(Protocol):
    # called before serialize
    def update_header(self, header: MessageHeader):
        pass

    def serialize(self, stream: BufferedIOBase):
        pass

    def deserialize(self, stream: BufferedIOBase, header: MessageHeader):
        pass

    @staticmethod
    def size(header: MessageHeader) -> int:
        pass


message_mapping: dict[MessageType, type[MessagePayload]]
message_mapping_inv: dict[type[MessagePayload], MessageType]


def message_size(header: MessageHeader) -> int:
    return message_mapping[header.type].size(header)


@dataclass
class MessageWrapper:
    header: MessageHeader
    payload: MessagePayload

    def __init__(self, header: MessageHeader, payload: MessagePayload = None):
        self.header = header
        self.payload = payload

    def serialize(self, stream: BufferedIOBase):
        self.payload.update_header(self.header)
        self.header.serialize(stream)
        self.payload.serialize(stream)

    def deserialize(self, stream: BufferedIOBase):
        self.payload = message_mapping[self.header.type]()
        self.payload.deserialize(stream, self.header)

    def payload_size(self) -> int:
        return message_size(self.header)


def wrap_message(
    payload: MessagePayload, network: NetworkInfo = DEFAULT_NETWORK
) -> MessageWrapper:
    payload_type = message_mapping_inv[type(payload)]
    header = MessageHeader(payload_type, network)
    wrapper = MessageWrapper(header, payload)
    return wrapper


@dataclass
class MessageKeepalive:
    # PAYLOAD
    peers: list[tuple[bytes, int]]  # 8 <ipv6, port> entries

    SIZE: ClassVar = 144

    def __init__(self, peers=None):
        # TODO
        self.peers = peers

    def update_header(self, header: MessageHeader):
        pass

    def serialize(self, stream: BufferedIOBase):
        assert len(self.peers) == 8
        for [ip, port] in self.peers:
            stream.write(ip)
            stream.write(port.to_bytes(2, "big"))

    def deserialize(self, stream: BufferedIOBase, header: MessageHeader):
        for _ in range(8):
            ip = stream.read(16)
            # TODO: Check endianess
            port = int.from_bytes(stream.read(2), "big")

    @staticmethod
    def size(header: MessageHeader) -> int:
        return MessageKeepalive.SIZE


@dataclass
class MessageHandshake:
    @dataclass
    class Response:
        # PAYLOAD
        account: bytes = None  # 32 bytes
        signature: bytes = None  # 64 bytes

        SIZE: ClassVar = 96  # account + signature

        def serialize(self, stream: BufferedIOBase):
            assert len(self.account) == 32
            assert len(self.signature) == 64

            stream.write(self.account)
            stream.write(self.signature)

        def deserialize(self, stream: BufferedIOBase, header: MessageHeader):
            self.account = stream.read(32)
            self.signature = stream.read(64)

    # PAYLOAD
    query: bytes  # 32 bytes
    response: Response

    QUERY_FLAG: ClassVar = 0
    RESPONSE_FLAG: ClassVar = 1

    def __init__(self, query: bytes = None, response: Response = None):
        self.query = query
        self.response = response

    def update_header(self, header: MessageHeader):
        if self.query:
            header.extensions.set(MessageHandshake.QUERY_FLAG)
        if self.response:
            header.extensions.set(MessageHandshake.RESPONSE_FLAG)

    def serialize(self, stream: BufferedIOBase):
        if self.query:
            assert len(self.query) == 32
            stream.write(self.query)
        if self.response:
            self.response.serialize(stream)

    def deserialize(self, stream: BufferedIOBase, header: MessageHeader):
        if MessageHandshake.is_query(header):
            self.query = stream.read(32)
        if MessageHandshake.is_response(header):
            self.response = MessageHandshake.Response()
            self.response.deserialize(stream, header)

    QUERY_SIZE: ClassVar = 32

    @staticmethod
    def size(header: MessageHeader) -> int:
        size = 0
        if MessageHandshake.is_query(header):
            size += MessageHandshake.QUERY_SIZE
        if MessageHandshake.is_response(header):
            size += MessageHandshake.Response.SIZE
        return size

    @staticmethod
    def is_query(header: MessageHeader) -> bool:
        return header.extensions.test(MessageHandshake.QUERY_FLAG)

    @staticmethod
    def is_response(header: MessageHeader) -> bool:
        return header.extensions.test(MessageHandshake.RESPONSE_FLAG)


@dataclass
class MessagePublish:
    # PAYLOAD
    block: BlockWrapper = None

    def update_header(self, header: MessageHeader):
        type = self.block.type.value
        header.extensions.value |= type << 8

    def serialize(self, stream: BufferedIOBase):
        self.block.serialize(stream)

    def deserialize(self, stream: BufferedIOBase, header: MessageHeader):
        type = MessagePublish.block_type(header)
        self.block = BlockWrapper(type)
        self.block.deserialize(stream)

    @staticmethod
    def size(header: MessageHeader) -> int:
        type = MessagePublish.block_type(header)
        size = BlockWrapper.block_size(type)
        return size

    @staticmethod
    def block_type(header: MessageHeader) -> BlockType:
        BLOCK_TYPE_MASK = 0x0F00
        type = (header.extensions.value & BLOCK_TYPE_MASK) >> 8
        return BlockType(type)


message_mapping = {
    MessageType.KEEPALIVE: MessageKeepalive,
    MessageType.NODE_ID_HANDSHAKE: MessageHandshake,
    MessageType.PUBLISH: MessagePublish,
}

# invert mapping
message_mapping_inv = {v: k for k, v in message_mapping.items()}


def serialize_message(message: MessageWrapper) -> bytes:
    with BytesIO() as stream:
        message.serialize(stream)
        stream.seek(0)
        data = stream.read()
        return data


def deserialize_header(data: bytes) -> tuple[MessageHeader, int]:
    with BytesIO(data) as stream:
        header = MessageHeader()
        header.deserialize(stream)
        # calculate message payload size
        size = message_size(header)
        return header, size


def deserialize_message(data: bytes, header: MessageHeader) -> MessageWrapper:
    with BytesIO(data) as stream:
        message = MessageWrapper(header)
        message.deserialize(stream)
        return message


def deserialize_message_with_header(data: bytes) -> MessageWrapper:
    with BytesIO(data) as stream:
        header_data = stream.read(MessageHeader.SIZE)
        header, size = deserialize_header(header_data)
        message = deserialize_message(stream, header)
        return message


if __name__ == "__main__":

    def test_handshake():
        payload = MessageHandshake(query=randbytes(32), response=None)
        original = wrap_message(payload)
        print("origi:", original)
        data = serialize_message(original)
        print("serialized:", data)
        final = deserialize_message_with_header(data)
        print("final:", final)

    test_handshake()

    print("done")
    pass
