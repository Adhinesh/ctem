import ipaddress
import re
from datetime import datetime, timedelta
from app import config

_domain_pattern = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

_submission_log = {}


class ValidationError(Exception):
    pass


def sanitize_target(target: str, target_type: str) -> str:
    if not target:
        return ""
    target = target.strip()
    # Strip protocol prefix
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]
    # Strip trailing slashes and paths for domain and ip
    if target_type in ("domain", "ip"):
        target = target.split("/")[0]
        # Strip port if present (e.g. example.com:8080 or 192.168.1.1:80)
        if ":" in target and not target.count(":") > 1:  # ignore IPv6 multiple colons
            target = target.split(":")[0]
    return target.strip().lower() if target_type == "domain" else target.strip()


def validate_target(target, target_type):
    if target_type not in config.TARGET_TYPES:
        raise ValidationError(f"unsupported target_type: {target_type}")

    target = sanitize_target(target, target_type)

    if not target:
        raise ValidationError("target cannot be empty")

    if target_type == "domain":
        if not _domain_pattern.match(target):
            raise ValidationError("malformed domain")
        return target

    if target_type == "ip":
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise ValidationError("malformed ip address")
        return target

    if target_type == "cidr":
        try:
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise ValidationError("malformed cidr block")
        return target

    if target_type == "cloud_project":
        if not re.match(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", target):
            raise ValidationError("malformed gcp project id")
        return target

    raise ValidationError("unsupported target_type")


def check_rate_limit(tenant_id):
    now = datetime.utcnow()
    window_start = now - timedelta(hours=1)

    submissions = _submission_log.get(tenant_id, [])
    submissions = [ts for ts in submissions if ts > window_start]

    if len(submissions) >= config.SCAN_RATE_LIMIT_PER_HOUR:
        return False

    submissions.append(now)
    _submission_log[tenant_id] = submissions
    return True


def is_declared_target(target, declared_targets):
    return target in declared_targets
