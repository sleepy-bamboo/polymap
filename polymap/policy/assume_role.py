from __future__ import annotations

import re
from polymap.policy.parser import iter_statements

def _ensure_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def _extract_aws_principals(principal_field) -> list[str]:
    """
    Trust policy Principal extraction (AWS principals only).
    Supports:
      Principal: "*"
      Principal: {"AWS": "..."} or {"AWS": ["...","..."]}
    """
    if principal_field is None:
        return []
    if principal_field == "*":
        return ["*"]
    if isinstance(principal_field, dict):
        aws = principal_field.get("AWS")
        if aws is None:
            return []
        if isinstance(aws, list):
            return [str(x) for x in aws]
        return [str(aws)]
    return []

def _account_id_from_arn(arn: str) -> str | None:
    m = re.search(r"arn:aws:iam::(\d+):", arn)
    return m.group(1) if m else None

def trust_allows_assume_role(
    trust_doc: dict | None,
    source_principal_arn: str,
    target_role_arn: str,
) -> tuple[bool, bool]:

    if not trust_doc:
        return (False, False)

    src_acct = _account_id_from_arn(source_principal_arn)
    ambiguous = False

    for st in iter_statements(trust_doc):
        if st.get("Effect") != "Allow":
            continue

        actions = [a.lower() for a in (st.get("Action") or [])]
        if not actions:
            continue

        
        if not any(a in ("sts:assumerole", "sts:*", "*") or a.endswith(":*") for a in actions):
            continue

        principals = _extract_aws_principals(st.get("Principal"))
        if not principals:
            continue

        if st.get("Condition") is not None:
            ambiguous = True

       
        if "*" in principals:
            return (True, True if ambiguous else False)

        
        if source_principal_arn in principals:
            return (True, True if ambiguous else False)

        
        if src_acct:
            root_arn = f"arn:aws:iam::{src_acct}:root"
            if root_arn in principals:
                return (True, True if ambiguous else False)

    return (False, False)
