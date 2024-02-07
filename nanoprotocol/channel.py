import asyncio
import argparse
from dataclasses import dataclass
from random import randbytes

import ed25519_blake2b

from . import messages
from .blocks import *
from .messages import *


async def read_exact(reader, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = await reader.read(size - len(data))
        if not chunk:
            raise ConnectionError("Socket connection broken")
        data += chunk
    return data


@dataclass
class Channel:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    async def send(self, message: MessagePayload):
        wrapped = messages.wrap_message(message)
        data = messages.serialize_message(wrapped)
        self.writer.write(data)
        await self.writer.drain()

    async def receive(self) -> MessagePayload:
        header_data = await read_exact(self.reader, MessageHeader.SIZE)
        assert len(header_data) == MessageHeader.SIZE

        header, message_size = messages.deserialize_header(header_data)

        message_data = await read_exact(self.reader, message_size)
        assert len(message_data) == message_size

        message = messages.deserialize_message(message_data, header)
        return message.payload

    async def publish_block(self, block: BlockWrapper):
        publish = messages.MessagePublish(block)
        await self.send(publish)

    @staticmethod
    async def connect(address: str, port: int) -> "Channel":
        reader, writer = await asyncio.open_connection(address, port)
        channel = Channel(reader, writer)

        async def create_query_response(cookie: bytes):
            signing_key, verifying_key = ed25519_blake2b.create_keypair()
            signature = signing_key.sign(cookie)
            return verifying_key.to_bytes(), signature

        async def handshake():
            query = randbytes(32)
            local_query = MessageHandshake(query=query)
            await channel.send(local_query)

            remote_response = await channel.receive()
            assert isinstance(remote_response, MessageHandshake)
            assert remote_response.query

            account, signature = await create_query_response(remote_response.query)
            local_response = MessageHandshake(response=MessageHandshake.Response(account, signature))
            await channel.send(local_response)

        await handshake()

        return channel


async def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--address", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=17075)
    args = parser.parse_args()

    async def test_channel(address, port):
        channel = await Channel.connect(address, port)
        print("connected:", channel)

        handshake = MessageHandshake(query=randbytes(32), response=None)

        print("sending handshake...")
        await channel.send(handshake)
        print("sent handshake")

        while True:
            response = await channel.receive()
            print("received:", response)

    await test_channel(args.address, args.port)


if __name__ == "__main__":
    asyncio.run(main())
