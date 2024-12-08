class PaginatedListViewMixin:
    paginate_by = 20
    max_page_size = 100

    PAGE_SIZE_CHOICES = [
        {"value": 20, "label": "20 per page"},
        {"value": 50, "label": "50 per page"},
        {"value": 100, "label": "100 per page"},
    ]

    def get_paginate_by(self, queryset=None):
        try:
            page_size = int(self.request.GET.get("page_size", self.paginate_by))
            if page_size <= 0:
                return self.paginate_by
            return min(page_size, self.max_page_size)
        except (ValueError, TypeError):
            return self.paginate_by

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        current_page_size = self.get_paginate_by()
        total_count = context["paginator"].count

        context.update(
            {
                "current_page_size": current_page_size,
                "page_size_choices": self.PAGE_SIZE_CHOICES,
                "total_count": total_count,
                "page_range": self._get_page_range(
                    context["paginator"], context["page_obj"].number
                ),
                "search": self.request.GET.get("search", ""),
            }
        )

        return context

    def _get_page_range(self, paginator, current_page, window=2):
        if paginator.num_pages <= 5:
            return range(1, paginator.num_pages + 1)

        pages = [1]
        if current_page > 3:
            pages.append("...")

        start_page = max(2, current_page - window)
        end_page = min(paginator.num_pages - 1, current_page + window)
        pages.extend(range(start_page, end_page + 1))

        if current_page < paginator.num_pages - 2:
            pages.append("...")

        if paginator.num_pages not in pages:
            pages.append(paginator.num_pages)

        return pages
