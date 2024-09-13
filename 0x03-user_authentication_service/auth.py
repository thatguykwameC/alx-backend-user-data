#!/usr/bin/env python3

"""Auth module"""

import bcrypt
from bcrypt import checkpw
import uuid
from db import DB
from user import User
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from typing import Union


def _hash_password(password: str) -> bytes:
    """Hashes a password using bcrypt."""
    hashed_pwd = bcrypt.hashpw(password.encode("utf-8"),
                               bcrypt.gensalt())
    return hashed_pwd


def _generate_uuid() -> str:
    """Generates a new UUID."""
    return str(uuid.uuid4())


class Auth:
    """
    The Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize a new Auth instance."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user."""
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate the user loging infos expects email and password
        Tries locating user by email
        Return:
            If matches returns True otherwise False
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                return checkpw(password.encode('utf-8'),
                               user.hashed_password)
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """
        Creates a new session for a user
        Returns:
            The session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets/Finds user by session ID."""
        user = None
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """Destroys a user session."""
        if user_id is not None:
            return self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """
        Generates a Reset password token
        Raises ValueError if no user found
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError("User not found")
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Updates the password according to a given user rest token
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid token!")
        new_passwd_hash = _hash_password(password)
        self._db.update_user(user.id,
                             hashed_password=new_passwd_hash,
                             reset_token=None)
