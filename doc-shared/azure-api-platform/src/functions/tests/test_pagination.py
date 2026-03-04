"""Unit tests for pagination utilities."""
import pytest

from shared.pagination import paginate_list


@pytest.mark.unit
class TestPaginateList:
    def test_first_page(self):
        items = list(range(25))
        result = paginate_list(items, page=1, page_size=10)
        assert result["items"] == list(range(10))
        assert result["page"] == 1
        assert result["page_size"] == 10
        assert result["total"] == 25
        assert result["total_pages"] == 3

    def test_middle_page(self):
        items = list(range(25))
        result = paginate_list(items, page=2, page_size=10)
        assert result["items"] == list(range(10, 20))

    def test_last_page(self):
        items = list(range(25))
        result = paginate_list(items, page=3, page_size=10)
        assert result["items"] == list(range(20, 25))
        assert len(result["items"]) == 5

    def test_page_beyond_range(self):
        items = list(range(5))
        result = paginate_list(items, page=10, page_size=10)
        assert result["items"] == []
        assert result["total"] == 5

    def test_empty_list(self):
        result = paginate_list([], page=1, page_size=10)
        assert result["items"] == []
        assert result["total"] == 0
        assert result["total_pages"] == 0

    def test_page_size_clamped_to_max(self):
        items = list(range(5))
        result = paginate_list(items, page=1, page_size=5000)
        assert result["page_size"] == 1000

    def test_page_zero_defaults_to_one(self):
        items = list(range(5))
        result = paginate_list(items, page=0, page_size=10)
        assert result["page"] == 1
        assert result["items"] == list(range(5))

    def test_negative_page_defaults_to_one(self):
        items = list(range(5))
        result = paginate_list(items, page=-3, page_size=10)
        assert result["page"] == 1
