import re
from urllib.parse import urlparse

from django import http
from django.utils.cache import patch_vary_headers
from django.utils.deprecation import MiddlewareMixin

from corsheaders.conf import conf
from corsheaders.signals import check_request_enabled

ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin"
ACCESS_CONTROL_EXPOSE_HEADERS = "Access-Control-Expose-Headers"
ACCESS_CONTROL_ALLOW_CREDENTIALS = "Access-Control-Allow-Credentials"
ACCESS_CONTROL_ALLOW_HEADERS = "Access-Control-Allow-Headers"
ACCESS_CONTROL_ALLOW_METHODS = "Access-Control-Allow-Methods"
ACCESS_CONTROL_MAX_AGE = "Access-Control-Max-Age"


class CorsMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """
        If CORS preflight header, then create an
        empty body response (200 OK) and return it

        Django won't bother calling any other request
        view/exception middleware along with the requested view;
        it will call any response middlewares
        """
        request._cors_enabled = self.is_enabled(request)
        if request._cors_enabled:

            if (
                request.method == "OPTIONS"
                and "HTTP_ACCESS_CONTROL_REQUEST_METHOD" in request.META
            ):
                response = http.HttpResponse()
                response["Content-Length"] = "0"
                return response

    def process_response(self, request, response):
        """
        Add the respective CORS headers
        """
        enabled = getattr(request, "_cors_enabled", None)
        if enabled is None:
            enabled = self.is_enabled(request)

        if not enabled:
            return response

        patch_vary_headers(response, ["Origin"])

        origin = request.META.get("HTTP_ORIGIN")
        if not origin:
            return response

        # todo: check hostname from db instead
        url = urlparse(origin)

        if conf.CORS_ALLOW_CREDENTIALS:
            response[ACCESS_CONTROL_ALLOW_CREDENTIALS] = "true"

        if (
            not conf.CORS_ORIGIN_ALLOW_ALL
            and not self.origin_found_in_white_lists(origin, url)
            and not self.check_signal(request)
        ):
            return response

        if conf.CORS_ORIGIN_ALLOW_ALL and not conf.CORS_ALLOW_CREDENTIALS:
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = "*"
        else:
            response[ACCESS_CONTROL_ALLOW_ORIGIN] = origin

        if len(conf.CORS_EXPOSE_HEADERS):
            response[ACCESS_CONTROL_EXPOSE_HEADERS] = ", ".join(
                conf.CORS_EXPOSE_HEADERS
            )

        if request.method == "OPTIONS":
            response[ACCESS_CONTROL_ALLOW_HEADERS] = ", ".join(conf.CORS_ALLOW_HEADERS)
            response[ACCESS_CONTROL_ALLOW_METHODS] = ", ".join(conf.CORS_ALLOW_METHODS)
            if conf.CORS_PREFLIGHT_MAX_AGE:
                response[ACCESS_CONTROL_MAX_AGE] = conf.CORS_PREFLIGHT_MAX_AGE

        return response

    def origin_found_in_white_lists(self, origin, url):
        return (
            (origin == "null" and origin in conf.CORS_ORIGIN_WHITELIST)
            or self._url_in_whitelist(url)
            or self.regex_domain_match(origin)
        )

    def regex_domain_match(self, origin):
        for domain_pattern in conf.CORS_ORIGIN_REGEX_WHITELIST:
            if re.match(domain_pattern, origin):
                return origin

    def is_enabled(self, request):
        return bool(
            re.match(conf.CORS_URLS_REGEX, request.path_info)
        ) or self.check_signal(request)

    def check_signal(self, request):
        signal_responses = check_request_enabled.send(sender=None, request=request)
        return any(return_value for function, return_value in signal_responses)

    def _url_in_whitelist(self, url):
        origins = [urlparse(o) for o in conf.CORS_ORIGIN_WHITELIST]
        return any(
            origin.scheme == url.scheme and origin.netloc == url.netloc
            for origin in origins
        )
