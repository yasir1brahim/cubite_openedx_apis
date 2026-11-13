"""Safe responses for operational errors in the Cubite API."""

import logging
import secrets

from rest_framework.response import Response

logger = logging.getLogger(__name__)
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def operation_failed(operation, exc, message, *, field="message"):
    reference = "NCEC-" + "".join(secrets.choice(ALPHABET) for _ in range(10))
    logger.error("cubite_operation_failed reference=%s operation=%s exception=%s",
                 reference, operation, type(exc).__name__)
    return Response({field: message, "code": "internal_error", "reference": reference}, status=500,
                    headers={"Cache-Control": "no-store"})
