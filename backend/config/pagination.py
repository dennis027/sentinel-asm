from rest_framework.pagination import PageNumberPagination


class DefaultPagination(PageNumberPagination):
    """
    25 per page by default; clients that need a fuller list (e.g. the
    asset picker on the Scanners page) can ask for up to 200 with
    ?page_size=.
    """

    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 200
