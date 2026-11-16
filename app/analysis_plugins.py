"""Trusted in-process adapters. Project contents are never imported or executed."""
from dataclasses import dataclass
from threading import RLock
import re


@dataclass(frozen=True)
class Adapter:
    id: str
    extensions: tuple
    analyze: object  # callable(path, relative_path) -> (entities, findings)


_adapters={}
_lock=RLock()


def register(adapter):
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,39}',adapter.id) or not callable(adapter.analyze):
        raise ValueError('Invalid analyzer')
    if not adapter.extensions or any(not re.fullmatch(r'\.[a-z0-9]+',x) for x in adapter.extensions):
        raise ValueError('Invalid extensions')
    with _lock:
        if adapter.id in _adapters or any(set(adapter.extensions)&set(a.extensions) for a in _adapters.values()):
            raise ValueError('Duplicate analyzer')
        _adapters[adapter.id]=adapter


def adapters():
    with _lock:return tuple(_adapters.values())


def for_path(path):
    return next((a for a in adapters() if path.suffix.lower() in a.extensions),None)
