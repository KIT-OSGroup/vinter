from collections import defaultdict
from itertools import combinations
from typing import Callable, Collection, Generator, Iterable, Optional, Tuple, TypeVar

import random

T = TypeVar("T")
_KT = TypeVar("_KT")
_VT = TypeVar("_VT")

# based on https://stackoverflow.com/a/54758488/1543768
def random_subset(iterable: Iterable[T], generator: random.Random) -> Generator[T, None, None]:
    for el in iterable:
        if generator.randint(0, 1) == 0:
            yield el
    # performance improvement if iterable allows random access: generate bit vector and then choose elements with 1


def powerset(items: Collection[T], strict: bool = False) -> Generator[Tuple[T, ...], None, None]:
    range_ = range(1, len(items)) if strict else range(len(items) + 1)
    for k in range_:
        yield from combinations(items, k)


class KeyProvidingDefaultDict(defaultdict):
    # TODO we're not using the same _KT and _VT as in defaultdict here
    _default_factory: Optional[Callable[[_KT], _VT]]  # a bit hacky since we're not even using defaultdict's default_factory... inherit from dict instead?

    def __init__(self, default_factory=None, **kwargs):  # typing could be improved, see type stubs of dict and defaultdict
        super().__init__(**kwargs)
        self._default_factory = default_factory

    def __missing__(self, key_):
        if self._default_factory:
            defaultdict.__setitem__(self, key_, self._default_factory(key_))
            return self[key_]
        else:
            super(KeyProvidingDefaultDict, self).__missing__(key_)
