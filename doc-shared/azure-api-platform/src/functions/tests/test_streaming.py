"""Unit tests for streaming utilities."""
import io
import json

import pytest

from shared.streaming import chunked_read, stream_json_array


@pytest.mark.unit
class TestStreamJsonArray:
    def test_empty_generator(self):
        result = b"".join(stream_json_array(iter([])))
        assert json.loads(result) == []

    def test_single_item(self):
        items = iter([{"id": 1, "name": "test"}])
        result = b"".join(stream_json_array(items))
        parsed = json.loads(result)
        assert len(parsed) == 1
        assert parsed[0]["id"] == 1

    def test_multiple_items(self):
        items = iter([{"id": i} for i in range(3)])
        result = b"".join(stream_json_array(items))
        parsed = json.loads(result)
        assert len(parsed) == 3
        assert [item["id"] for item in parsed] == [0, 1, 2]

    def test_produces_valid_json(self):
        items = iter([{"key": "value"}, {"key": "other"}])
        result = b"".join(stream_json_array(items))
        # Should not raise
        json.loads(result)


@pytest.mark.unit
class TestChunkedRead:
    def test_reads_in_chunks(self):
        data = b"a" * 100
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=30))
        assert len(chunks) == 4  # 30+30+30+10
        assert b"".join(chunks) == data

    def test_empty_stream(self):
        stream = io.BytesIO(b"")
        chunks = list(chunked_read(stream, chunk_size=10))
        assert chunks == []

    def test_stream_smaller_than_chunk(self):
        data = b"small"
        stream = io.BytesIO(data)
        chunks = list(chunked_read(stream, chunk_size=1024))
        assert len(chunks) == 1
        assert chunks[0] == data
