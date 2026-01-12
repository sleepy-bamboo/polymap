from __future__ import annotations
import fnmatch

def _ensure_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def match_any(patterns: list[str], value: str) -> bool:
    if not patterns:
        return False
    v = value.lower()
    return any(fnmatch.fnmatchcase(v, p.lower()) for p in patterns)

def statement_matches_identity(stmt, action: str, resource: str) -> tuple[bool, bool]:
    """
    Returns (matches, ambiguous).
    MVP: if Condition exists => ambiguous (we don't fully evaluate conditions yet).
    """
    not_action = _ensure_list(stmt.get("NotAction"))
    action_list = _ensure_list(stmt.get("Action"))
    not_resource = _ensure_list(stmt.get("NotResource"))
    resource_list = _ensure_list(stmt.get("Resource"))

    if not_action and match_any(not_action, action):
        return (False, False)
    if action_list and not match_any(action_list, action):
        return (False, False)

    if not_resource and match_any(not_resource, resource):
        return (False, False)
    if resource_list and not match_any(resource_list, resource):
        return (False, False)

    ambiguous = stmt.get("Condition") is not None
    return (True, ambiguous)

def extract_principals_from_resource_statement(stmt) -> list[str]:
    """
    Extract principal ARNs/"*" from a resource-based policy statement.
    Returns list of principal strings (e.g., arn:aws:iam::123:role/X, "*" etc.)
    """
    p = stmt.get("Principal")
    if p is None:
        return []
    if p == "*":
        return ["*"]
    if isinstance(p, dict):
        out = []
        aws = p.get("AWS")
        if aws is not None:
            if isinstance(aws, list):
                out.extend(aws)
            else:
                out.append(aws)
        return out
    return []
