"""Streaming utilities for large data responses."""
import json
from collections.abc import Generator


def stream_json_array(items: Generator[dict, None, None]) -> Generator[bytes, None, None]:
    """
    Stream a JSON array from a generator, yielding chunks suitable for
    chunked transfer encoding.

    Yields:
        Bytes chunks forming a valid JSON array.
    """
    yield b"["
    first = True
    for item in items:
        if not first:
            yield b","
        yield json.dumps(item, default=str).encode("utf-8")
        first = False
    yield b"]"


def chunked_read(stream, chunk_size: int = 4 * 1024 * 1024) -> Generator[bytes, None, None]:
    """
    Read a stream in fixed-size chunks (default 4MB).

    Args:
        stream: A file-like or blob download stream.
        chunk_size: Size of each chunk in bytes.

    Yields:
        Bytes chunks from the stream.
    """
    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break
        yield chunk
