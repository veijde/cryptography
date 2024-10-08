import requests
import base64
import os
from nacl.hash import blake2b
import nacl.encoding

BASE_URL = "https://g5qrhxi4ni.execute-api.eu-west-1.amazonaws.com/Prod/hash"


def create_hash_challenge():
    response = requests.post(BASE_URL)
    response.raise_for_status()
    return response.json()


def solve_hash_challenge(challenge):
    message_base64: bytes = challenge['message']
    message_bytes = base64.b64decode(message_base64)

    prefix_bytes = find_valid_prefix(message_bytes)
    if prefix_bytes is None:
        raise Exception("No valid prefix found!")

    prefix_base64 = base64.b64encode(prefix_bytes).decode('utf-8')

    solution = {
        "prefix": prefix_base64
    }

    response = requests.delete(
        f"{BASE_URL}/{challenge['challengeId']}", json=solution)

    if response.status_code == 200:
        print("Challenge solved!")
    else:
        print("Failed to solve the challenge.")


def find_valid_prefix(message_bytes):
    while True:
        prefix_bytes = os.urandom(4)
        combined = prefix_bytes + message_bytes
        hash_value = blake2b(combined, encoder=nacl.encoding.RawEncoder)

        if hash_value[:2] == b'\x00\x00':
            print(hash_value)
            return prefix_bytes


if __name__ == "__main__":
    challenge = create_hash_challenge()
    print(f"Challenge created: {challenge}")

    solve_hash_challenge(challenge)
