"""Live JSON views; each write is validated and applied by the Rust object."""

from collections.abc import Mapping, MutableMapping, MutableSequence
from operator import index as integer_index
from sys import maxsize

_MISSING = object()


def _slice_parts(key):
    def bound(value):
        return None if value is None else max(-maxsize - 1, min(maxsize, integer_index(value)))

    step = 1 if key.step is None else bound(key.step)
    if step == 0:
        raise ValueError("slice step cannot be zero")
    return bound(key.start), bound(key.stop), step


def _plain(value):
    if isinstance(value, _View):
        return value.copy()
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def view(owner, path):
    value = owner._get(path)
    if isinstance(value, dict):
        return _DictView(owner, tuple(path))
    if isinstance(value, list):
        return _ListView(owner, tuple(path))
    return value


class _View:
    __slots__ = ("_owner", "_path")

    def __init__(self, owner, path):
        self._owner, self._path = owner, path

    def copy(self):
        """Return detached JSON data for an application adapter."""
        return self._owner._get(self._path)

    def __len__(self):
        return len(self.copy())

    def __repr__(self):
        return repr(self.copy())

    def __eq__(self, other):
        return self.copy() == _plain(other)


class _DictView(_View, MutableMapping):
    def setdefault(self, key, default=None):
        if key not in self.copy():
            self[key] = default
        return self[key]

    def pop(self, key, default=_MISSING):
        if key not in self.copy():
            if default is _MISSING:
                raise KeyError(key)
            return default
        return self._owner._take((*self._path, key))

    def popitem(self):
        keys = self.copy()
        if not keys:
            raise KeyError("popitem(): mapping is empty")
        key = next(reversed(keys))
        return key, self._owner._take((*self._path, key))

    def __getitem__(self, key):
        if key not in self.copy():
            raise KeyError(key)
        return view(self._owner, (*self._path, key))

    def __setitem__(self, key, value):
        if not isinstance(key, str):
            raise TypeError("governed JSON keys must be strings")
        self._owner._set((*self._path, key), _plain(value))

    def __delitem__(self, key):
        if key not in self.copy():
            raise KeyError(key)
        self._owner._delete((*self._path, key))

    def __iter__(self):
        return iter(self.copy())


class _ListView(_View, MutableSequence):
    def _index(self, key):
        key = integer_index(key)
        length = len(self)
        if key < 0:
            key += length
        if key < 0 or key >= length:
            raise IndexError("list index out of range")
        return key

    def __getitem__(self, key):
        if isinstance(key, slice):
            return [self[i] for i in range(*key.indices(len(self)))]
        return view(self._owner, (*self._path, self._index(key)))

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            parts = _slice_parts(key)
            values = [_plain(item) for item in value]
            self._owner._slice(self._path, *parts, values, False)
        else:
            self._owner._set((*self._path, self._index(key)), _plain(value))

    def __delitem__(self, key):
        if isinstance(key, slice):
            self._owner._slice(self._path, *_slice_parts(key), [], True)
        else:
            self._owner._delete((*self._path, self._index(key)))

    def insert(self, index, value):
        self._owner._insert(self._path, integer_index(index), _plain(value))

    def append(self, value):
        self._owner._append(self._path, _plain(value))

    def extend(self, values):
        values = [_plain(item) for item in values]
        self._owner._extend(self._path, values)

    def pop(self, index=-1):
        return self._owner._take((*self._path, self._index(index)))

    def reverse(self):
        self._owner._reverse(self._path)
