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

    def get_paginate_by(self, queryset=None):
        """
        Get the number of items to paginate by from the request.
        """
        try:
            page_size = int(self.request.GET.get("page_size", self.paginate_by))
            if page_size <= 0:
                return self.paginate_by
            return min(page_size, self.max_page_size)
        except (ValueError, TypeError):
            return self.paginate_by

    def get_pagination_context(self, paginator, page_obj):
        """
        Generate pagination-related context data, preserving filters.
        """
        if not paginator or not page_obj:
            return {}

        current_page_size = self.get_paginate_by()
        total_count = paginator.count

        query_params = self.request.GET.copy()
        query_params.pop("page", None)

        base_query_string = query_params.urlencode()
        base_url = f"?{base_query_string}" if base_query_string else "?"

        pages = []
        if paginator.num_pages <= 5:
            pages = [str(i) for i in range(1, paginator.num_pages + 1)]
        else:
            pages.append("1")

            if page_obj.number > 3:
                pages.append("...")

            start_page = max(2, page_obj.number - 2)
            end_page = min(paginator.num_pages - 1, page_obj.number + 2)
            pages.extend(str(i) for i in range(start_page, end_page + 1))

            if page_obj.number < paginator.num_pages - 2:
                pages.append("...")

            if str(paginator.num_pages) not in pages:
                pages.append(str(paginator.num_pages))

        return {
            "current_page_size": current_page_size,
            "page_size_choices": self.PAGE_SIZE_CHOICES,
            "total_count": total_count,
            "page_range": pages,
            "search": self.request.GET.get("search", ""),
            "base_url": base_url,
            "previous_page_url": f"{base_url}&page={page_obj.previous_page_number}"
            if page_obj.has_previous()
            else None,
            "next_page_url": f"{base_url}&page={page_obj.next_page_number}"
            if page_obj.has_next()
            else None,
        }

    def get_context_data(self, **kwargs):
        """
        Add pagination context to the existing context data.
        """
        context = super().get_context_data(**kwargs)
        paginator = context.get("paginator")
        page_obj = context.get("page_obj")
        pagination_context = self.get_pagination_context(paginator, page_obj)
        context.update(pagination_context)

        return context
