def key_label(func):
    def add_label(self, k, *args):
        _k = "{}{}".format(self.label, k)
        return func(self, _k, *args)

    return add_label


class SetGetDict(dict):
    def set(self, key, value):
        self[key] = value

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default

    def delete(self, item):
        del self[item]


class LabeledDict():
    def __init__(self, label=''):
        self.storage = SetGetDict()

        if label == '':
            self.label = label
            self.label_len = 0
        else:
            self.label = '__{}__'.format(label)
            self.label_len = len(self.label)

    @key_label
    def get(self, k, default=None):
        return self.storage.get(k, default)

    @key_label
    def update(self, ava):
        return self.storage.update(ava)

    @key_label
    def __getitem__(self, k):
        return self.storage.get(k)

    @key_label
    def __setitem__(self, k, v):
        return self.storage.set(k, v)

    @key_label
    def __delitem__(self, k):
        del self.storage[k]

    @key_label
    def __contains__(self, k):
        return self.storage.__contains__(k)

    def __iter__(self):
        for key, val in self.storage.__iter__():
            if key.startswith(self.label):
                yield key[self.label_len:], val

    def keys(self):
        return [k[self.label_len:] for k in self.storage.keys() if k.startswith(self.label)]
