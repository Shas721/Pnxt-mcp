from services.pointnxt_api import PointNXTAPI


def get_api() -> PointNXTAPI:
    return PointNXTAPI()


def check_backend_health() -> dict:
    """Check PointNXT backend reachability and latency."""
    return get_api().check_backend_health()


def check_authentication() -> dict:
    """Check whether the configured PointNXT authentication is valid."""
    return get_api().check_authentication()


def check_configuration() -> dict:
    """Check whether required PointNXT configuration is present."""
    return get_api().check_configuration()
