import os
import threading
import pathlib
import contextlib
import logging

from typing import Optional, Protocol, runtime_checkable, cast
from collections.abc import Callable, Generator

from dataclasses import dataclass, field
from watchdog.events import LoggingEventHandler, FileSystemEvent, DirModifiedEvent, FileModifiedEvent
from watchdog.observers import ObserverType, Observer
from watchdog.observers.api import BaseObserver

logger = logging.getLogger(__name__)

type Parser[T, S] = Callable[[S], T]
type ModifiedEvent = DirModifiedEvent | FileModifiedEvent


@runtime_checkable
class Proxy[T](Protocol):
    __subject__: T


class BaseProxy[T](Proxy[T]):
    def __getattr__(self, name):
        return getattr(self.__subject__, name)

    def __getitem__(self, key):
        assert hasattr(self.__subject__, "__getitem__")
        return self.__subject__[key]

    @classmethod
    def create[**P](cls, *args: P.args, **kwargs: P.kwargs) -> T:
        return cast(T, cls(*args, **kwargs))


@dataclass
class FileProxy[T](BaseProxy[T], LoggingEventHandler):
    path: str
    parser: Parser[T, str]
    mutex: threading.Lock = field(default_factory=threading.Lock)
    __subject__: T = field(init=False)

    def __post_init__(self):
        LoggingEventHandler.__init__(self, logger=logging.getLogger(type(self).__name__))
        self.update()

    def __hash__(self):
        return hash((self.path, self.parser))

    @property
    def event_filter(self) -> list[type[FileSystemEvent]]:
        return [FileModifiedEvent]

    @property
    def content(self) -> str:
        return pathlib.Path(self.path).read_text()

    def update(self):
        with self.mutex:
            self.__subject__ = self.parser(self.content)

    def on_modified(self, event: ModifiedEvent):
        super().on_modified(event)

        match event:
            case FileModifiedEvent() if os.fsdecode(event.src_path) == os.path.realpath(self.path):
                self.update()


@dataclass
class LiteralProxy[T, S](BaseProxy[T]):
    content: S
    parser: Parser[T, S] = lambda content: content  # type: ignore[assignment,return-value]
    __subject__: T = field(init=False)

    def __post_init__(self):
        self.__subject__ = self.parser(self.content)


@contextlib.contextmanager
def observer[T](
    *proxies: Proxy[T],
    cls: ObserverType = Observer,
) -> Generator[BaseObserver]:
    observer = cls()
    for proxy in proxies:
        if isinstance(proxy, FileProxy):
            observer.schedule(proxy, os.path.dirname(proxy.path), recursive=True, event_filter=proxy.event_filter)

    try:
        observer.start()
        yield observer
    finally:
        if observer.is_alive():
            observer.stop()
        observer.join()


def create_proxy[T](content: Optional[str], path: os.PathLike, parser: Parser[T, str], default: str) -> T:
    if content is not None:
        return LiteralProxy.create(content, parser=parser)

    if (file := pathlib.Path(path)).is_file():
        return FileProxy.create(f"{file}", parser=parser)

    return LiteralProxy.create(default, parser=parser)
