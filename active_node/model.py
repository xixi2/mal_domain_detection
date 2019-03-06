from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from common.mysql_config import DBSession, engine


Base = declarative_base()


class DnsAnswer(Base):
    __tablename__ = 'dns_answer'
    id = Column(Integer, autoincrement=True, primary_key=True)
    domain_name = Column(String(250))
    TTL = Column(Integer)
    ip = Column(String(20))


class AuthAnswer(Base):
    __tablename__ = 'dns_auth_answer'
    id = Column(Integer, autoincrement=True, primary_key=True)
    domain_name = Column(String(250))
    TTL = Column(Integer)
    name_server = Column(String(250))


class AddAnswer(Base):
    __tablename__ = 'dns_add_answer'
    id = Column(Integer, autoincrement=True, primary_key=True)
    name_server = Column(String(250))
    TTL = Column(Integer)
    ip = Column(String(20))


def create_table():
    Base.metadata.create_all(engine)


if __name__ == '__main__':
    session = DBSession()
    create_table()
