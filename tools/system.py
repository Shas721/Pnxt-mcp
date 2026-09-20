from services.pointnxt_api import PointNXTAPI


api = PointNXTAPI()


def check_backend_health() -> dict:
    """Check PointNXT backend reachability and latency."""
    return api.check_backend_health()


def check_authentication() -> dict:
    """Check whether the configured PointNXT authentication is valid."""
    return api.check_authentication()


def check_configuration() -> dict:
    """Check whether required PointNXT configuration is present."""
    return api.check_configuration()
