import datetime
import json

import sqlalchemy as alchemy_db
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker

PlainDict = dict

class AbstractStorageSQLAlchemy:
    def __init__(self, conf_dict):
        self.engine = alchemy_db.create_engine(conf_dict['url'])
        self.connection = self.engine.connect()
        self.metadata = alchemy_db.MetaData()
        self.table = alchemy_db.Table(conf_dict['params']['table'],
                                      self.metadata, autoload=True,
                                      autoload_with=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = scoped_session(Session)

    def get(self, k):
        entry = self.session.query(self.table).filter_by(owner=k).first()
        if entry is None:
            return None
        return entry.data

    def set(self, k, v):
        self.delete(k)
        ins = self.table.insert().values(owner=k,
                                         data=v)
        self.session.execute(ins)
        self.session.commit()
        return 1

    def update(self, k, v):
        """
            k = value_to_match
            v = value_to_be_substituted
        """
        upquery = self.table.update(). \
            where(self.table.c.owner == k). \
            values(**{'data': v})
        self.session.execute(upquery)
        self.session.commit()
        return 1

    def delete(self, v):
        """
        return the count of deleted objects
        """
        delquery = self.table.delete().where(self.table.c.owner == v)
        n_entries = self.session.query(self.table).filter(self.table.c.owner == v).count()
        self.session.execute(delquery)
        return n_entries

    def __contains__(self, k):
        for entry in self():
            if k in entry:
                return 1

    def __call__(self):
        return self.session.query(self.table).all()

    def __iter__(self):
        return self.session.query(self.table)

    def __str__(self):
        entries = []
        for entry in self():
            l = []
            for element in entry:
                if isinstance(element, datetime.datetime):
                    l.append(element.isoformat())
                else:
                    l.append(element)
            entries.append(l)
        return json.dumps(entries, indent=2)

    def flush(self):
        """
        make a decision here ...
        """
        try:
            self.session.commit()
        except:
            self.session.rollback()
            self.session.flush()

    def __setitem__(self, k, v):
        return self.set(k, v)
