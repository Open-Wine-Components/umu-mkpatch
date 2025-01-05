from enum import StrEnum
from typing import TypedDict


class FileType(StrEnum):
    # All file types currently supported under mtree
    # See mtree(1)
    File = "file"
    Block = "block"
    Char = "char"
    Dir = "dir"
    Fifo = "fifo"
    Link = "link"
    Socket = "socket"


class Item(TypedDict):
    # Path to file, 'target', relative to the Proton build base
    name: str
    # File type per mtree(1)
    type: FileType
    # Expected digest as str after applying the binary difference to 'source'
    xxhash: int
    # Value containing the binary difference between 'source' and 'target'
    # Depending on the section the value can be a path or bz2 compressed data
    data: bytes
    # Unsigned int, base 10 and non-octal
    mode: int
    time: float
    size: int


class Manifest(TypedDict):
    xxhash: int
    name: str
    mode: int
    size: int
    time: float


class CustomDataItem(TypedDict):
    source: str
    target: str
    manifest: list[Manifest]
    update: list[Item]
    delete: list[Item]
    add: list[Item]


class CustomDataItemContainer(TypedDict):
    contents: list[CustomDataItem]
    signature: tuple[bytes, bytes]
    public_key: tuple[bytes, bytes]
