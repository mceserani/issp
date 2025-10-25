# Implement the CBC block cipher mode of operation for AES256 and use it to ensure
# the confidentiality of messages exchanged between Alice and Bob.
#
# Hints:
# - You may use the `pkcs7_pad` and `pkcs7_unpad` functions from the `issp` module for
#   a secure and unambiguous padding scheme.

import os

from issp import Actor, Channel, Message, log, pkcs7_pad, pkcs7_unpad, aes256_encrypt_block, aes256_decrypt_block

BLOCK_SIZE = 16


def xor(a: bytes, b: bytes) -> bytes:
    axb = bytes(ai ^ bi for ai, bi in zip(a, b, strict=False))
    return axb

def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    # TO-DO: Implement AES256 CBC encryption.
    data = aes256_encrypt_block(xor(data,iv),key)
    return data


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    # TO-DO: Implement AES256 CBC decryption.
    data = aes256_decrypt_block(xor(data,iv),key)
    return data


def alice(channel: Channel, key: bytes) -> None:
    msg = Message("Alice", "Bob", "Here is the top-secret PIN, keep it safe: 42")
    log.info("[Alice] Encrypted: %s", msg)
    # TO-DO: Generate a random IV, encrypt the message body, and prepend the IV to the ciphertext.
    iv = os.urandom(BLOCK_SIZE)
    msg.body = pkcs7_pad(msg.body, BLOCK_SIZE)
    cdata = bytearray()
    cdata.extend(iv)
    for i in range(0,len(msg.body),BLOCK_SIZE):
        block = xor(iv,msg.body[i:i+BLOCK_SIZE])
        block = aes256_encrypt_block(block,key)
        iv = block
        cdata.extend(block)
    msg.body = cdata
    channel.send(msg)


def bob(channel: Channel, key: bytes) -> None:
    msg = channel.receive("Bob")
    # TO-DO: Extract the IV from the beginning of the message body and decrypt the ciphertext.
    iv = msg.body[:BLOCK_SIZE]
    msg.body = msg.body[BLOCK_SIZE:]
    pdata = bytearray()
    for i in range(0,len(msg.body),BLOCK_SIZE):
        block = msg.body[i:i+BLOCK_SIZE]
        next_iv = block
        block = aes256_decrypt_block(block,key)
        block = xor(iv,msg.body[i:i+BLOCK_SIZE])
        iv = next_iv
        pdata.extend(block)
    msg.body = pkcs7_unpad(bytes(pdata), BLOCK_SIZE)
    log.info("[Bob] Decrypted: %s", msg)


def mallory(channel: Channel) -> None:
    channel.peek()


def main() -> None:
    key = os.urandom(32)
    Actor.start(Actor(alice, data=(key,)), Actor(bob, data=(key,)), Actor(mallory, priority=1))


if __name__ == "__main__":
    main()
