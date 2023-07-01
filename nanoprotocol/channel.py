import argparse
import socket
from ast import arg
from dataclasses import dataclass
from email import message
from random import randbytes

import ed25519_blake2b

from . import messages
from .blocks import BlockWrapper
from .messages import MessageHandshake, MessageHeader, MessagePayload, MessageWrapper


def read_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        data += sock.recv(size - len(data))
        # print("read:", len(data))
    return data


@dataclass
class Channel:
    sock: socket.socket

    def send(self, message: MessagePayload):
        # print("sending:", message)
        wrapped = messages.wrap_message(message)
        data = messages.serialize_message(wrapped)
        self.sock.sendall(data)

    def receive(self) -> MessagePayload:
        header_data = read_exact(self.sock, MessageHeader.SIZE)
        assert len(header_data) == MessageHeader.SIZE

        header, message_size = messages.deserialize_header(header_data)
        # print("message size:", message_size)

        message_data = read_exact(self.sock, message_size)
        assert len(message_data) == message_size

        message = messages.deserialize_message(message_data, header)
        return message.payload

    def publish_block(self, block: BlockWrapper):
        # print("publish block:", block)
        publish = messages.MessagePublish(block)
        self.send(publish)

    @staticmethod
    def connect(address: str, port: int) -> "Channel":
        sock = socket.create_connection((address, port))
        # print("socket:", sock)

        channel = Channel(sock)

        def create_query_response(cookie: bytes):
            signing_key, verifying_key = ed25519_blake2b.create_keypair()
            signature = signing_key.sign(cookie)
            return verifying_key.to_bytes(), signature

        def handshake():
            query = randbytes(32)
            local_query = MessageHandshake(query=query)
            channel.send(local_query)

            remote_response = channel.receive()
            # we need to complete remote server query to establish realtime channel
            assert isinstance(remote_response, MessageHandshake)
            assert remote_response.query
            # print("handshake response:", remote_response)

            account, signature = create_query_response(remote_response.query)
            local_response = MessageHandshake(response=MessageHandshake.Response(account, signature))
            channel.send(local_response)

        handshake()
        # print("handshake done")

        return channel


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", type=str, default="localhost")
    parser.add_argument("--port", type=int, default=17075)
    args = parser.parse_args()

    def test_channel(address, port):
        channel = Channel.connect(address, port)

        handshake = MessageHandshake(query=randbytes(32), response=None)
        print("sent:", handshake)

        channel.send(handshake)

        while True:
            response = channel.receive()
            print("response:", response)

    test_channel(args.address, args.port)

    pass
