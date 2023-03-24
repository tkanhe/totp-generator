import base64
import hmac
import struct
import time

totp_key = "RHA5IABFBOHZF3OIGJXI7N7KJYTRFVGT"


def totp(key, time_step=30, digits=6, digest="sha1"):
    key = base64.b32decode(key.upper() + "=" * ((8 - len(key)) % 8))
    counter = struct.pack(">Q", int(time.time() / time_step))
    mac = hmac.new(key, counter, digest).digest()
    offset = mac[-1] & 0x0F
    binary = struct.unpack(">L", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(binary)[-digits:].zfill(digits)


if __name__ == "__main__":
    print(totp(totp_key))
