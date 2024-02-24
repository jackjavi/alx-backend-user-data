#!/usr/bin/env python3
""" Authentication Module """

import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a password with a salt using bcrypt.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)

    return hashed_password
