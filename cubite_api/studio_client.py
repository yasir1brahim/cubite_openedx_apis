"""The LMS contract for confirmed Studio course-creator cleanup."""

from urllib.parse import urlsplit

import requests
from django.conf import settings


class StudioConfigurationInvalid(Exception):
    pass


class StudioCleanupUnconfirmed(Exception):
    pass


def studio_origin():
    try:
        raw = settings.CMS_ROOT_URL
        if not isinstance(raw, str) or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in raw):
            raise ValueError
        origin = urlsplit(raw)
        configured = urlsplit("//" + settings.CMS_BASE)
        lms_scheme = urlsplit(settings.LMS_ROOT_URL).scheme
        if (
            origin.scheme not in {"http", "https"} or origin.scheme != lms_scheme
            or not origin.hostname or origin.username is not None or origin.password is not None
            or (origin.hostname, origin.port) != (configured.hostname, configured.port)
            or origin.path not in {"", "/"} or "?" in raw or "#" in raw
        ):
            raise ValueError
        return raw.rstrip("/")
    except (AttributeError, TypeError, ValueError) as exc:
        raise StudioConfigurationInvalid from exc


def confirm_creator_cleanup(user, authorization):
    target = studio_origin() + "/api/contentstore/v2/delete/course_creator"
    try:
        response = requests.delete(
            target,
            json={"target_user_id": user.pk, "email": user.email, "username": user.username},
            headers={"Authorization": authorization},
            timeout=5,
            allow_redirects=False,
        )
        if response.status_code != 200:
            raise StudioCleanupUnconfirmed
        confirmation = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise StudioCleanupUnconfirmed from exc
    if (
        not isinstance(confirmation, dict) or confirmation.get("cleanup_confirmed") is not True
        or type(confirmation.get("target_user_id")) is not int or confirmation["target_user_id"] != user.pk
    ):
        raise StudioCleanupUnconfirmed
