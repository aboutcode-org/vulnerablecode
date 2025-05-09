import logging
import re

from django.core.paginator import EmptyPage
from django.core.paginator import PageNotAnInteger
from django.core.paginator import Paginator
from django.db.models.query import QuerySet
from rest_framework.pagination import PageNumberPagination

logger = logging.getLogger(__name__)


class SmallResultSetPagination(PageNumberPagination):
    page_size_query_param = "page_size"
    max_page_size = 100


class PaginatedListViewMixin:
    """
    A mixin that adds pagination functionality to ListView-based views.
    """

    paginate_default = 20
    max_page_size = 100
    page_size_choices = [
        {"value": 20, "label": "20 per page"},
        {"value": 50, "label": "50 per page"},
        {"value": 100, "label": "100 per page"},
    ]

    max_pages_without_truncation = 5  # it is a value for number of pages without truncation like is total number of pages are less than this number the pagination will show all pages.
    pages_around_current = 2  # number of pages to be shown around current page
    truncation_threshold_start = 4  # it is a threshold for start of truncation
    truncation_threshold_end = 3  # it is a threshold for end of truncation

    def get_queryset(self):
        """
        Ensure a queryset is always available
        """
        try:
            queryset = super().get_queryset()
        except Exception as e:
            logger.error(f"Error in get_queryset: {e}")
            return self.model.objects.none()

        if not queryset or not isinstance(queryset, QuerySet):
            queryset = self.model.objects.none()
        return queryset

    def sanitize_page_size(self, raw_page_size):
        """
        Sanitize page size input to prevent XSS and injection attempts.
        """
        if not raw_page_size:
            return self.paginate_default

        clean_page_size = re.sub(
            r"\D", "", str(raw_page_size)
        )  # it remove all non-digit characters like if 50abcd is their then it takes out 50
        if not clean_page_size:
            return self.paginate_default

        try:
            page_size = int(clean_page_size)
        except (ValueError, TypeError):
            logger.info("Invalid page_size input attempted")
            return self.paginate_default

        valid_sizes = {choice["value"] for choice in self.page_size_choices}
        if page_size not in valid_sizes:
            logger.warning(f"Attempted to use unauthorized page size: {page_size}")
            return self.paginate_default

        return page_size

    def get_paginate_by(self, queryset=None):
        """
        Get the number of items to paginate by from the request.
        """
        raw_page_size = self.request.GET.get("page_size")
        return self.sanitize_page_size(raw_page_size)

    def get_page_range(self, paginator, page_obj):
        """
        Generate a list of page numbers for navigation
        """
        num_pages = paginator.num_pages
        current_page = page_obj.number
        if num_pages <= self.max_pages_without_truncation:
            return list(map(str, range(1, num_pages + 1)))
        pages = [1]

        if current_page > self.truncation_threshold_start:
            pages.append("...")
        start = max(2, current_page - self.pages_around_current)
        end = min(num_pages - 1, current_page + self.pages_around_current)
        pages.extend(range(start, end + 1))
        if current_page < num_pages - self.truncation_threshold_end:
            pages.append("...")
        if num_pages > 1:
            pages.append(num_pages)
        return list(map(str, pages))

    def paginate_queryset(self, queryset, page_size):
        if not queryset:
            queryset = self.model.objects.none()
        paginator = Paginator(queryset, page_size)
        try:
            page_number = int(self.request.GET.get("page", "1"))
        except (ValueError, TypeError):
            logger.error("Invalid page number input")
            page_number = 1
        page_number = max(1, min(page_number, paginator.num_pages))
        try:
            page = paginator.page(page_number)
        except (EmptyPage, PageNotAnInteger) as e:
            logger.error(f"Specific pagination error: {e}")
            page = paginator.page(1)
        return (paginator, page, page.object_list, page.has_other_pages())

    def get_context_data(self, **kwargs):
        """
        Return a mapping of pagination-related context data, preserving filters.
        """
        queryset = kwargs.pop("queryset", None) or self.get_queryset()
        page_size = self.get_paginate_by()
        paginator, page, object_list, is_paginated = self.paginate_queryset(queryset, page_size)
        page_range = self.get_page_range(paginator, page)

        context = super().get_context_data(
            object_list=object_list,
            page_obj=page,
            paginator=paginator,
            is_paginated=is_paginated,
            **kwargs,
        )

        previous_page_url = page.previous_page_number() if page.has_previous() else None
        next_page_url = page.next_page_number() if page.has_next() else None
        context.update(
            {
                "current_page_size": page_size,
                "page_size_choices": self.page_size_choices,
                "total_count": paginator.count,
                "page_range": page_range,
                "search": self.request.GET.get("search", ""),
                "previous_page_url": previous_page_url,
                "next_page_url": next_page_url,
            }
        )
        return context
