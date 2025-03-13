import logging
import re

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

    paginate_by = 20
    max_page_size = 100
    PAGE_SIZE_CHOICES = [
        {"value": 20, "label": "20 per page"},
        {"value": 50, "label": "50 per page"},
        {"value": 100, "label": "100 per page"},
    ]

    def get_queryset(self):
        """
        Ensure a queryset is always available
        """
        try:
            queryset = super().get_queryset()
            if not queryset:
                queryset = self.model.objects.all()
            if not isinstance(queryset, QuerySet):
                queryset = self.model.objects.all()
            return queryset
        except Exception as e:
            logger.error(f"Error in get_queryset: {e}")
            return self.model.objects.all()

    def sanitize_page_size(self, raw_page_size):
        """
        Sanitize page size input to prevent XSS and injection attempts.
        """
        if not raw_page_size:
            return self.paginate_by
        clean_page_size = re.sub(r"\D", "", str(raw_page_size))
        try:
            page_size = int(clean_page_size) if clean_page_size else self.paginate_by
            valid_sizes = {choice["value"] for choice in self.PAGE_SIZE_CHOICES}
            if page_size not in valid_sizes:
                logger.warning(f"Attempted to use unauthorized page size: {page_size}")
                return self.paginate_by
            return page_size
        except (ValueError, TypeError):
            logger.info("Empty or invalid page_size input attempted")
            return self.paginate_by

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
        if num_pages <= 7:
            return list(range(1, num_pages + 1))
        pages = []
        pages.append(1)
        if current_page > 4:
            pages.append("...")
        start = max(2, current_page - 2)
        end = min(num_pages - 1, current_page + 2)
        pages.extend(range(start, end + 1))
        if current_page < num_pages - 3:
            pages.append("...")
        if num_pages > 1:
            pages.append(num_pages)
        return [str(p) for p in pages]

    def paginate_queryset(self, queryset, page_size):
        try:
            if not queryset or queryset.count() == 0:
                queryset = self.model.objects.all()
            paginator = Paginator(queryset, page_size)
            page_params = self.request.GET.getlist("page")
            page_number = page_params[-1] if page_params else "1"
            try:
                page_number = int(re.sub(r"\D", "", str(page_number)))
                if not page_number:
                    page_number = 1
            except (ValueError, TypeError):
                page_number = 1
            page_number = max(1, min(page_number, paginator.num_pages))
            page = paginator.page(page_number)
            return (paginator, page, page.object_list, page.has_other_pages())
        except Exception as e:
            logger.error(f"Pagination error: {e}")
            queryset = self.model.objects.all()
            paginator = Paginator(queryset, page_size)
            page = paginator.page(1)
            return (paginator, page, page.object_list, page.has_other_pages())

    def get_context_data(self, **kwargs):
        """
        Return a mapping of pagination-related context data, preserving filters.
        """
        queryset = self.get_queryset()
        page_size = self.get_paginate_by()
        paginator, page, object_list, is_paginated = self.paginate_queryset(queryset, page_size)
        page_range = self.get_page_range(paginator, page)

        search = self.request.GET.get("search", "")

        context = super().get_context_data(
            object_list=object_list,
            page_obj=page,
            paginator=paginator,
            is_paginated=is_paginated,
            **kwargs,
        )

        context.update(
            {
                "current_page_size": page_size,
                "page_size_choices": self.PAGE_SIZE_CHOICES,
                "total_count": paginator.count,
                "page_range": page_range,
                "search": search,
                "previous_page_url": page.previous_page_number() if page.has_previous() else None,
                "next_page_url": page.next_page_number() if page.has_next() else None,
            }
        )
        return context
