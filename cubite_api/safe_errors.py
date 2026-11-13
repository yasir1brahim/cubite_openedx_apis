"""Safe responses for operational errors in the Cubite API."""

import logging
import secrets

from django.core.exceptions import PermissionDenied
from django.http import Http404
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import APIView, set_rollback

logger = logging.getLogger(__name__)
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def operation_failed(operation, exc, message, *, field="message"):
    reference = "NCEC-" + "".join(secrets.choice(ALPHABET) for _ in range(10))
    logger.error("cubite_operation_failed reference=%s operation=%s exception=%s",
                 reference, operation, type(exc).__name__)
    return Response({field: message, "code": "internal_error", "reference": reference}, status=500,
                    headers={"Cache-Control": "no-store"})


class CubiteAPIView(APIView):
    """Keep normal API errors and report unexpected failures with a reference."""

    def handle_exception(self, exc):
        if isinstance(exc, (Http404, PermissionDenied)) or (
            isinstance(exc, APIException) and exc.status_code < 500
        ):
            return super().handle_exception(exc)
        set_rollback()
        return operation_failed(type(self).__name__, exc, "The request could not be completed.")
