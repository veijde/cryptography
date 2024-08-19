import requests
import base64
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError

BASE_URL = "https://g5qrhxi4ni.execute-api.eu-west-1.amazonaws.com/Prod/decrypt"


def create_decrypt_challenge():
    response = requests.post(BASE_URL)
    response.raise_for_status()
    return response.json()


def solve_decrypt_challenge(challenge):
    ciphertext_base64 = challenge['ciphertext']
    key_base64 = challenge['key']
    nonce_base64 = challenge['nonce']

    ciphertext = base64.b64decode(ciphertext_base64)
    key = base64.b64decode(key_base64)
    nonce = base64.b64decode(nonce_base64)

    try:
        box = SecretBox(key)
        plaintext = box.decrypt(ciphertext, nonce)
    except CryptoError as e:
        raise Exception(f"Decryption failed: {e}")

    plaintext_base64 = base64.b64encode(plaintext).decode('utf-8')

    solution = {"plaintext": plaintext_base64}

    response = requests.delete(
        f"{BASE_URL}/{challenge['challengeId']}", json=solution)
    response.raise_for_status()

    if response.status_code == 200:
        print("Challenge solved!")
    elif (response.status_code == 204):
        checkChallenge = requests.get(f"{BASE_URL}/{challenge['challengeId']}")
        if (checkChallenge.status_code == 404):
            print("Challenge solved!")
    else:
        print("Failed to solve the challenge.")


if __name__ == "__main__":
    challenge = create_decrypt_challenge()
    print(f"Challenge created: {challenge}")

    solve_decrypt_challenge(challenge)
