#!/usr/bin/env python3

"""Database module."""

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError

from user import Base, User


class DB:
    """Database class."""

    def __init__(self) -> None:
        """Initialize a new DB instance."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Session object to query the database"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Method that adds a new user."""
        new_user = User(email=email, hashed_password=hashed_password)
        self._session.add(new_user)
        self._session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Method that finds a user by arbitrary keyword args."""
        if not kwargs:
            raise InvalidRequestError("No query args are passed")
        try:
            user = self._session.query(User).filter_by(**kwargs).one()
        except NoResultFound:
            raise NoResultFound("User does not exist!")
        except InvalidRequestError:
            raise InvalidRequestError("Wrong query args are passed")
        return user

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Method that updates a usr by its id with arbitrary keyword args.
        """
        fields = {col.name for col in User.__table__.columns}
        for k in kwargs:
            if k not in fields:
                raise ValueError("Invalid attr: {}".format(k))
        user = self.find_user_by(id=user_id)

        for k, val in kwargs.items():
            setattr(user, k, val)

        self._session.commit()
