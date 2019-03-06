from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
engine = create_engine("mysql+pymysql://root:123456@192.168.1.167:3306/maldom")
DBSession = sessionmaker(bind=engine)