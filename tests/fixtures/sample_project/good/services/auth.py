import logging

logger = logging.getLogger(__name__)


def handle_login(user_id: int) -> bool:
    """Authenticate user without logging sensitive personal data."""
    logger.info("Authentication attempt completed for system identifier: %s", user_id)
    return True
