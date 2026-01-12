from __future__ import annotations

def ensure_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]

def iter_statements(policy_doc: dict):
    for st in ensure_list(policy_doc.get("Statement")):
        yield {
            "Effect": st.get("Effect", "Deny"),
            "Action": ensure_list(st.get("Action")),
            "NotAction": ensure_list(st.get("NotAction")),
            "Resource": ensure_list(st.get("Resource")),
            "NotResource": ensure_list(st.get("NotResource")),
            "Principal": st.get("Principal"),
            "NotPrincipal": st.get("NotPrincipal"),
            "Condition": st.get("Condition"),
            "Sid": st.get("Sid"),
        }

