import base64
import binascii
import hashlib

import nanolib


def hexify_account(account: str) -> bytes:
    hex_key = nanolib.get_account_public_key(account_id=account)
    return hex_key
