from __future__ import annotations

import re
from polymap.policy.parser import iter_statements
from polymap.policy.matcher import statement_matches_identity, extract_principals_from_resource_statement, match_any
from polymap.policy.assume_role import trust_allows_assume_role


S3_ACTIONS = ["s3:ListBucket", "s3:GetObject"]

def tags_to_dict(tagset: list[dict]) -> dict[str, str]:
    d = {}
    for t in tagset or []:
        k = str(t.get("Key", "")).strip()
        v = str(t.get("Value", "")).strip()
        if k:
            d[k.lower()] = v
    return d

def is_break_glass_role(role_name: str, role_tags: list[dict]) -> bool:
    td = tags_to_dict(role_tags)
    if td.get("breakglass", "").lower() in ("1", "true", "yes"):
        return True
    return bool(re.search(r"(break[-_ ]?glass|emergency)", role_name, flags=re.I))

def trust_is_sso(trust_doc: dict | None, role_name: str) -> bool:
    if role_name.startswith("AWSReservedSSO_"):
        return True
    if not trust_doc:
        return False
    for st in iter_statements(trust_doc):
        acts = st["Action"]
        if any(a.lower() == "sts:assumerolewithsaml" for a in acts):
            return True
        princ = st.get("Principal") or {}
        fed = None
        if isinstance(princ, dict):
            fed = princ.get("Federated")
        if isinstance(fed, str) and ":saml-provider/" in fed:
            return True
    return False

def trust_is_ci(trust_doc: dict | None) -> bool:
    if not trust_doc:
        return False
    for st in iter_statements(trust_doc):
        acts = [a.lower() for a in st["Action"]]
        if "sts:assumerolewithwebidentity" in acts:
            return True
    return False

def is_critical_bucket(bucket: dict) -> bool:
    name = bucket["name"]
    if name.startswith("prod-"):
        return True
    td = tags_to_dict(bucket.get("tags", []))
    env = (td.get("environment") or td.get("env") or td.get("stage") or "").lower()
    if env == "prod" or env == "production":
        return True
    cls = (td.get("dataclassification") or td.get("classification") or td.get("data_classification") or "").lower()
    if cls in ("confidential", "restricted", "pii", "sensitive"):
        return True
    return False

def bucket_high_risk_signals(bucket: dict, account_id):
    signals = []

    pab = bucket.get("public_access_block")
    if pab is None:
        signals.append({"type": "PAB_MISSING_OR_UNREADABLE", "detail": "No PublicAccessBlock config (or AccessDenied)."})
    else:
        for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
            if pab.get(k) is False:
                signals.append({"type": "PAB_WEAK", "detail": f"{k}=false"})

    pol = bucket.get("policy")
    if isinstance(pol, dict):
        for st in iter_statements(pol):
            principals = extract_principals_from_resource_statement(st)
            if "*" in principals:
                signals.append({"type": "BUCKET_POLICY_PUBLIC_PRINCIPAL", "detail": f"Sid={st.get('Sid')}"})
            if account_id:
                for pr in principals:
                    m = re.search(r"arn:aws:iam::(\d+):", str(pr))
                    if m and m.group(1) != account_id:
                        signals.append({"type": "BUCKET_POLICY_CROSS_ACCOUNT", "detail": pr})

    acl = bucket.get("acl")
    if isinstance(acl, dict):
        grants = acl.get("Grants") or []
        for g in grants:
            grantee = g.get("Grantee") or {}
            uri = grantee.get("URI")
            gtype = grantee.get("Type")
            perm = g.get("Permission")
            if uri and ("AllUsers" in uri or "AuthenticatedUsers" in uri):
                signals.append({"type": "ACL_PUBLIC_OR_AUTH_USERS", "detail": f"{uri} {perm}"})
            if gtype == "CanonicalUser" and perm and perm != "FULL_CONTROL":
                signals.append({"type": "ACL_NON_OWNER_GRANT", "detail": f"{perm}"})

    return signals


def _extract_principals(principal_field) -> list[str]:
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


def _principal_matches(principal_arn: str, principals: list[str]) -> bool:
    if "*" in principals:
        return True
    if principal_arn in principals:
        return True
    acct = _account_id_from_arn(principal_arn)
    if acct:
        if acct in principals:
            return True
        root_arn = f"arn:aws:iam::{acct}:root"
        if root_arn in principals:
            return True
    return False


def statement_matches_resource(stmt, principal_arn: str, action: str, resource: str) -> tuple[bool, bool]:
    not_action = stmt.get("NotAction") or []
    action_list = stmt.get("Action") or []
    not_resource = stmt.get("NotResource") or []
    resource_list = stmt.get("Resource") or []

    not_principals = _extract_principals(stmt.get("NotPrincipal"))
    principals = _extract_principals(stmt.get("Principal"))

    if not_principals:
        if _principal_matches(principal_arn, not_principals):
            return (False, False)
    elif principals:
        if not _principal_matches(principal_arn, principals):
            return (False, False)
    else:
        return (False, False)

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


def eval_resource_bucket(
    policy_doc: dict | None,
    principal_arn: str,
    action: str,
    resource: str,
    ambiguous_as_allowed: bool,
):
    if not isinstance(policy_doc, dict):
        return "NO_MATCH"

    any_allow = False
    any_amb = False

    for st in iter_statements(policy_doc):
        matches, amb = statement_matches_resource(st, principal_arn, action, resource)
        if not matches:
            continue
        if amb:
            any_amb = True
        if st["Effect"] == "Deny":
            return "DENIED"
        if st["Effect"] == "Allow":
            any_allow = True

    if any_allow and any_amb:
        return "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional allow as allowed until conditions are evaluated.
    if any_allow:
        return "ALLOWED"
    if any_amb:
        return "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional-only matches as allowed until conditions are evaluated.
    return "NO_MATCH"


def eval_identity(docs, action, resource, ambiguous_as_allowed: bool):
    any_allow = False
    any_amb = False

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        for st in iter_statements(doc):
            matches, amb = statement_matches_identity(st, action, resource)
            if not matches:
                continue
            if amb:
                any_amb = True
            if st["Effect"] == "Deny":
                if amb:
                    continue
                return "DENIED"
            if st["Effect"] == "Allow":
                any_allow = True

    if any_allow and any_amb:
        return "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional allow as allowed until conditions are evaluated.
    if any_allow:
        return "ALLOWED"
    if any_amb:
        return "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional-only matches as allowed until conditions are evaluated.
    return "NO_MATCH"

def analyze_access(iam_data: dict, s3_data: dict, ambiguous_as_allowed: bool = True) -> dict:
    roles = []
    for r in iam_data["roles"]:
        role_obj = r["role"]
        docs = [p["document"] for p in r["inline"] if p.get("document")]
        for ap in r["attached"]:
            pol = iam_data["policies"].get(ap.get("PolicyArn"))
            if pol and pol.get("document"):
                docs.append(pol["document"])

        roles.append({
            "arn": role_obj["Arn"],
            "name": role_obj["RoleName"],
            "kind": "role",
            "trust": r.get("trust"),
            "tags": r.get("tags", []),
            "docs": docs,
        })

    entrypoints = []
    for rr in roles:
        if is_break_glass_role(rr["name"], rr["tags"]):
            entrypoints.append({**rr, "entrypoint_type": "break-glass"})
        elif trust_is_sso(rr["trust"], rr["name"]):
            entrypoints.append({**rr, "entrypoint_type": "sso"})
        elif trust_is_ci(rr["trust"]):
            entrypoints.append({**rr, "entrypoint_type": "ci"})

    role_principals = list(roles)

    assume_role_edges = []
    for src in entrypoints:
        src_docs = src.get("docs", [])
        src_arn = src["arn"]

        for tgt in role_principals:
            tgt_arn = tgt["arn"]
            if tgt_arn == src_arn:
                continue

            id_verdict = eval_identity(src_docs, "sts:AssumeRole", tgt_arn, ambiguous_as_allowed)
            if id_verdict == "NO_MATCH":
                continue
            if id_verdict == "DENIED":
                pass

            trust_allowed, trust_amb = trust_allows_assume_role(tgt.get("trust"), src_arn, tgt_arn)
            if not trust_allowed:
                continue

            combined = "ALLOWED"
            if id_verdict == "DENIED":
                combined = "DENIED"
            elif id_verdict == "AMBIGUOUS" or trust_amb:
                combined = "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional assume-role as allowed until conditions are evaluated.

            assume_role_edges.append({
                "source_arn": src_arn,
                "source_name": src.get("name"),
                "source_kind": src.get("kind"),
                "source_entrypoint_type": src.get("entrypoint_type"),

                "target_role_arn": tgt_arn,
                "target_role_name": tgt.get("name"),

                "verdict": combined,
                "details": {
                    "identity_side": id_verdict,
                    "trust_side_ambiguous": bool(trust_amb),
                },
            })


    buckets = []
    account_id_hint = None
    if roles:
        import re
        m = re.search(r"arn:aws:iam::(\d+):role/", roles[0]["arn"])
        if m:
            account_id_hint = m.group(1)

    for b in s3_data["buckets"]:
        crit = is_critical_bucket(b)
        signals = bucket_high_risk_signals(b, account_id_hint)
        buckets.append({
            "name": b["name"],
            "critical": crit,
            "high_risk": len(signals) > 0,
            "risk_signals": signals,
            "raw": {
                "tags": b.get("tags", []),
                "public_access_block": b.get("public_access_block"),
                "has_policy": b.get("policy") is not None,
                "has_acl": b.get("acl") is not None,
            }
        })
    access_edges = []
    bucket_by_name = {b.get("name"): b for b in s3_data.get("buckets", []) if b.get("name")}

    def _eval_s3_for_principal(principal: dict, bucket_name: str):
        bucket_arn = f"arn:aws:s3:::{bucket_name}"
        obj_arn = f"{bucket_arn}/*"

        rows = []
        bucket = bucket_by_name.get(bucket_name)
        bucket_policy = bucket.get("policy") if bucket else None
        for act in S3_ACTIONS:
            res = bucket_arn if act == "s3:ListBucket" else obj_arn
            id_verdict = eval_identity(principal["docs"], act, res, ambiguous_as_allowed)
            res_verdict = eval_resource_bucket(bucket_policy, principal["arn"], act, res, ambiguous_as_allowed)

            if id_verdict == "DENIED" or res_verdict == "DENIED":
                verdict = "DENIED"
            elif id_verdict == "AMBIGUOUS" or res_verdict == "AMBIGUOUS":
                verdict = "DENIED" if ambiguous_as_allowed else "AMBIGUOUS"  # AMBIGUOUS: treat conditional allow as allowed until conditions are evaluated.
            elif id_verdict == "ALLOWED" or res_verdict == "ALLOWED":
                verdict = "ALLOWED"
            else:
                verdict = "NO_MATCH"

            if verdict != "NO_MATCH":
                rows.append({
                    "action": act,
                    "resource": res,
                    "verdict": verdict,
                    "identity_verdict": id_verdict,
                    "resource_verdict": res_verdict,
                })
        return rows

    target_bucket_names = [b["name"] for b in buckets if b["critical"] or b["high_risk"]]

    for ep in entrypoints:
        for bn in target_bucket_names:
            rows = _eval_s3_for_principal(ep, bn)
            if rows:
                access_edges.append({
                    "principal_arn": ep["arn"],
                    "principal_name": ep["name"],
                    "principal_kind": ep["kind"],
                    "principal_type": "entrypoint",
                    "entrypoint_type": ep.get("entrypoint_type"),
                    "bucket": bn,
                    "matches": rows,
                })

    role_access_edges = []
    for rolep in role_principals:
        for bn in target_bucket_names:
            rows = _eval_s3_for_principal(rolep, bn)
            if rows:
                role_access_edges.append({
                    "principal_arn": rolep["arn"],
                    "principal_name": rolep["name"],
                    "principal_kind": "role",
                    "principal_type": "role",
                    "bucket": bn,
                    "matches": rows,
                })

    return {
        "entrypoints": entrypoints,
        "roles": roles,
        "buckets": buckets,
        "assume_role": assume_role_edges,
        "access": access_edges,
        "role_access": role_access_edges,
        "notes": [
            "Conditions in IAM statements are treated as denied (AMBIGUOUS) for now." if ambiguous_as_allowed else "Conditions in IAM statements are treated as AMBIGUOUS for now."
        ],
    }
