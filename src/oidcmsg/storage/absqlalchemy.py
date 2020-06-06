import datetime
import json

import sqlalchemy as alchemy_db
from sqlalchemy.orm import sessionmaker

from oidcmsg.storage.db_setup import Base


class AbstractStorageSQLAlchemy:
    def __init__(self, conf_dict):
        self.engine = alchemy_db.create_engine(conf_dict['url'])
        self.connection = self.engine.connect()
        Base.metadata.create_all(self.engine)
        self.metadata = alchemy_db.MetaData()
        self.table = alchemy_db.Table(conf_dict['params']['table'],
                                      self.metadata, autoload=True,
                                      autoload_with=self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def get(self, k):
        entries = self.session.query(self.table).filter_by(owner=k).all()
        result = self._data_from_db(entries)
        return result

    def _data_from_db(self, entries):
        result = []
        for entry in entries:
            try:
                data = json.loads(entry.data)
                if isinstance(data, list):
                    result.extend(data)
                else:
                    result.append(data)
            except:
                result.append(entry.data)
        return result

    def _data_to_db(self, v):
        if isinstance(v, dict) or isinstance(v, list):
            value = json.dumps(v)
        else:
            value = v
        return value

    def set(self, k, v):
        value = self._data_to_db(v)
        ins = self.table.insert().values(owner=k,
                                         data=value)
        self.session.execute(ins)
        self.session.commit()
        return 1

    def update(self, k, v, col_match='owner', col_value='data'):
        """
            k = value_to_match
            v = value_to_be_substituted
        """
        value = self._data_to_db(v)
        table_column = getattr(self.table.c, col_match)
        upquery = self.table.update(). \
            where(table_column == k). \
            values(**{col_value: value})
        self.session.execute(upquery)
        self.session.commit()
        return 1

    def delete(self, v, k='owner'):
        """
        return the count of deleted objects
        """
        table_column = getattr(self.table.c, k)
        delquery = self.table.delete().where(table_column == v)
        n_entries = self.session.query(self.table).filter(table_column == v).count()
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
