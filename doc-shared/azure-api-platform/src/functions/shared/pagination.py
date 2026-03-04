"""Pagination utilities for API responses."""
from typing import Any


def paginate_list(
    items: list[Any],
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    """
    Apply offset-based pagination to an in-memory list.

    Args:
        items: Full list of items.
        page: 1-indexed page number.
        page_size: Number of items per page.

    Returns:
        Dict with paginated items, page info, and total count.
    """
    page = max(page, 1)
    page_size = max(min(page_size, 1000), 1)
    total = len(items)
    start = (page - 1) * page_size
    end = start + page_size

    return {
        "items": items[start:end],
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": (total + page_size - 1) // page_size,
    }
