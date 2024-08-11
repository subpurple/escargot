import hashlib
import secrets
import base64
import binascii
from typing import Dict, Optional, Tuple, Any, List, Type
from enum import IntEnum

HASHERS: Dict[str, Type['Hasher']] = {}


class Hasher:
    # Can't leave it as None or mypy will complain
    algorithm = 'unknown'
    separator = '$'

    @classmethod
    def encode(cls, password: str, *stuff: Any, salt: Optional[str] = None) -> str:
        assert password is not None
        if salt is None:
            salt = gen_salt()
        assert cls.separator not in salt
        (hash_bytes, other_stuff) = cls._encode_impl(password, *stuff, salt=salt)
        hash = base64.b64encode(hash_bytes).decode('ascii').strip()
        return cls.separator.join([cls.algorithm] + other_stuff + [salt, hash])

    @classmethod
    def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
        raise NotImplementedError('Hasher._encode_impl')

    @classmethod
    def extract_salt(cls, encoded: str) -> Optional[str]:
        return encoded.split(cls.separator)[-2]

    @classmethod
    def extract_hash(cls, encoded: str) -> bytes:
        hash = encoded.split(cls.separator)[-1]
        return base64.b64decode(hash)

    @classmethod
    def verify(cls, password: str, encoded: str) -> bool:
        try:
            (algorithm, *stuff, salt, _) = encoded.split(cls.separator)
        except ValueError:
            return False

        try:
            hasher = HASHERS[algorithm]
        except KeyError:
            return False

        assert algorithm == hasher.algorithm
        encoded_2 = hasher.encode(password, *stuff, salt=salt)
        return secrets.compare_digest(encoded, encoded_2)


class PBKDF2PasswordHasher(Hasher):
    algorithm = 'pbkdf2_sha256'
    iterations = 24000

    @classmethod
    def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
        assert len(stuff) <= 1
        iterations: Optional[int] = (stuff[0] if stuff else None)
        if iterations is None:
            iterations = cls.iterations
        iterations = int(iterations)
        hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations, None)
        return hash, [str(iterations)]


class MD5PasswordHasher(Hasher):
    algorithm = 'md5'
    digest = hashlib.md5

    @classmethod
    def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
        assert not stuff
        assert salt is not None
        md5 = hashlib.md5()
        md5.update((salt + password).encode('utf-8'))
        return md5.digest(), []

    @classmethod
    def verify_hash(cls, hash_1: str, encoded: str) -> bool:
        try:
            (_, _, hash) = encoded.split(cls.separator)
        except ValueError:
            return False
        hash = binascii.hexlify(base64.b64decode(hash)).decode('ascii')
        return secrets.compare_digest(hash_1, hash)


class MD5CryptPasswordHasher(Hasher):
    algorithm = 'md5crypt'

    @classmethod
    def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
        from util.unixmd5crypt import unix_md5_crypt
        assert not stuff
        return unix_md5_crypt(password, salt), []

    @classmethod
    def encode(cls, password: str, *stuff: Any, salt: Optional[str] = None) -> str:
        assert not stuff
        assert salt is not None
        # MD5Crypt salts CAN contain the MD5Crypt magic, which contain the 'seperator.' Remove if found.
        if salt[:3] == '$1$': salt = salt[3:]
        # Shorten the salt to 8 characters
        salt = salt[:8]
        return super().encode(password, salt=salt)


class MD5BucpPasswordHasher(Hasher):
    algorithm = 'md5bucp'
    digest = hashlib.md5

    @classmethod
    def _encode_impl(cls, password: str, *stuff: Any, salt: str) -> Tuple[bytes, List[str]]:
        new_flag: Optional[int] = (stuff[0] if stuff else None)
        if new_flag is None:
            new_flag = 0

        md5 = hashlib.md5()

        if new_flag == 0:  # if we are not using new BUCP hash format
            md5.update(salt.encode() + password.encode() + b'AOL Instant Messenger (SM)')
        else:
            md5_pw = (hashlib
                      .md5(password.encode())
                      .digest())

            md5.update(salt.encode() + md5_pw + b'AOL Instant Messenger (SM)')

        return md5.digest(), []

    @classmethod
    def verify_hash(cls, hash_1: bytes, encoded: str) -> bool:
        try:
            (_, _, hash) = encoded.split(cls.separator)
        except ValueError:
            return False

        return secrets.compare_digest(hash_1.hex(), base64.b64decode(hash).hex())


HASHERS[PBKDF2PasswordHasher.algorithm] = PBKDF2PasswordHasher
HASHERS[MD5PasswordHasher.algorithm] = MD5PasswordHasher
HASHERS[MD5CryptPasswordHasher.algorithm] = MD5CryptPasswordHasher
HASHERS[MD5BucpPasswordHasher.algorithm] = MD5BucpPasswordHasher


def gen_salt(length: int = 15) -> str:
    return secrets.token_hex(length)[:length]


hasher = PBKDF2PasswordHasher
hasher_md5 = MD5PasswordHasher
hasher_md5crypt = MD5CryptPasswordHasher
hasher_md5bucp = MD5BucpPasswordHasher
