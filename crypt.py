import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os



def hash_division(hash: bytes) -> tuple[bytes, bytes]:
    part1 = secrets.token_bytes(len(hash))
    part2 = bytes(h ^ p for h, p in zip(hash, part1))

    return part1, part2


def hash_reconstruct(part1: bytes, part2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(part1, part2))


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """
    Returns:
        (private_key_raw, public_key_raw)
    """

    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()

    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )


def asym_encrypt_key(secret_key: bytes, public_key: bytes) -> bytes:
    """Encrypts a secret key using recipient's X25519 public key and AES-GCM."""

    # Генерируем временную (ephemeral) пару ключей
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                           format=serialization.PublicFormat.Raw)

    # Загружаем публичный ключ получателя
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(public_key)

    # Вычисляем общий секрет ECDH
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    salt = os.urandom(32)

    # Производный ключ для AES-GCM через HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'x25519-ecies-v1-aes256',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)

    # Шифрование с использованием AES-GCM
    nonce = os.urandom(12)
    ciphertext_with_tag = AESGCM(aes_key).encrypt(
        nonce,
        secret_key,
        associated_data=None  # можно добавить binding данных
    )

    # формат: salt + ephemeral_pub + nonce + ciphertext
    return salt + ephemeral_public_key + nonce + ciphertext_with_tag


def asym_decrypt_key(encrypted_key: bytes, private_key: bytes) -> bytes:
    """Decrypts a secret key using X25519 private key and AES-GCM."""

    # Разбор компонентов из входных данных
    salt = encrypted_key[:32]
    ephemeral_public_key = encrypted_key[32:64]
    nonce = encrypted_key[64:76]
    ciphertext_with_tag = encrypted_key[76:]

    # Загружаем ключи
    private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)
    ephemeral_pubkey = x25519.X25519PublicKey.from_public_bytes(
        ephemeral_public_key)

    # Вычисляем общий секрет ECDH
    shared_secret = private_key_obj.exchange(ephemeral_pubkey)

    # Производный ключ для AES-GCM через HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'x25519-ecies-v1-aes256',
        backend=default_backend()
    )

    # Расшифровка с использованием AES-GCM
    aes_key = hkdf.derive(shared_secret)

    # если tag неверный → автоматически exception
    return AESGCM(aes_key).decrypt(
        nonce,
        ciphertext_with_tag,
        associated_data=None
    )


def sym_encrypt_key(secret: bytes, aes_key: bytes) -> bytes:
    assert len(secret) == 32
    assert len(aes_key) == 32

    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(secret) + encryptor.finalize()
    return iv + encrypted_key


def sym_decrypt_key(ciphertext: bytes, aes_key: bytes) -> bytes:
    assert len(ciphertext) == 48
    assert len(aes_key) == 32

    iv = ciphertext[:16]
    encrypted_key = ciphertext[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key) + decryptor.finalize()
