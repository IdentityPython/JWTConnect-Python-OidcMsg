import datetime

import sqlalchemy as alchemy_db
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Thing(Base):
    __tablename__ = 'thing'

    id = alchemy_db.Column(alchemy_db.Integer,
                           alchemy_db.Sequence('thing_id_seq'),
                           primary_key=True)
    owner = alchemy_db.Column(alchemy_db.String(80),
                              unique=False, nullable=False)
    data = alchemy_db.Column(alchemy_db.String(4096),
                             unique=False, nullable=False)
    created = alchemy_db.Column(alchemy_db.DateTime,
                                default=datetime.datetime.utcnow)

    def __repr__(self):
        return '<Thing owned by %r>' % self.owner


def create_database(conf_dict):
    engine = alchemy_db.create_engine(conf_dict['url'])
    connection = engine.connect()
    Base.metadata.create_all(engine)
