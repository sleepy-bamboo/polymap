from __future__ import annotations

from botocore.exceptions import ClientError

# ---------- small helpers ----------

def _safe_call(fn, *args, **kwargs):
    """
    Wrapper: returns (ok, result_or_error_code)
    """
    try:
        return True, fn(*args, **kwargs)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        return False, code

def _arn_set_add(s: set[str], arn: str | None):
    if arn:
        s.add(arn)

# ---------- collectors ----------

def collect_iam(session_and_cfg):

    session, cfg = session_and_cfg
    iam = session.client("iam", config=cfg)

    data: dict = {
        "users": [],
        "groups": [],
        "roles": [],
        "policies": {},  # PolicyArn -> {policy, document(default_version)}
    }

    managed_policy_arns: set[str] = set()

    # ---- Users ----
    user_p = iam.get_paginator("list_users")
    for page in user_p.paginate():
        for u in page.get("Users", []):
            uname = u["UserName"]

            # attached user policies
            ok, resp = _safe_call(iam.list_attached_user_policies, UserName=uname)
            attached = resp.get("AttachedPolicies", []) if ok else []
            for ap in attached:
                _arn_set_add(managed_policy_arns, ap.get("PolicyArn"))

            # inline user policies
            ok, resp = _safe_call(iam.list_user_policies, UserName=uname)
            inline_names = resp.get("PolicyNames", []) if ok else []
            inline = []
            for pn in inline_names:
                ok2, resp2 = _safe_call(iam.get_user_policy, UserName=uname, PolicyName=pn)
                if ok2:
                    inline.append({"name": pn, "document": resp2.get("PolicyDocument")})

            # access keys (metadata only; no secrets)
            ok, resp = _safe_call(iam.list_access_keys, UserName=uname)
            access_keys = resp.get("AccessKeyMetadata", []) if ok else []

            # groups for user (names only)
            ok, resp = _safe_call(iam.list_groups_for_user, UserName=uname)
            groups_for_user = [g.get("GroupName") for g in (resp.get("Groups", []) if ok else [])]

            data["users"].append({
                "user": u,
                "attached": attached,
                "inline": inline,
                "access_keys": access_keys,
                "groups": groups_for_user,
            })

    # ---- Groups ----
    group_p = iam.get_paginator("list_groups")
    for page in group_p.paginate():
        for g in page.get("Groups", []):
            gname = g["GroupName"]

            # group members (for mapping group->users)
            members = []
            gm_p = iam.get_paginator("get_group")
            # get_group returns group + users; paginate users
            for gm_page in gm_p.paginate(GroupName=gname):
                for gu in gm_page.get("Users", []):
                    members.append(gu.get("UserName"))

            # attached group policies
            ok, resp = _safe_call(iam.list_attached_group_policies, GroupName=gname)
            attached = resp.get("AttachedPolicies", []) if ok else []
            for ap in attached:
                _arn_set_add(managed_policy_arns, ap.get("PolicyArn"))

            # inline group policies
            ok, resp = _safe_call(iam.list_group_policies, GroupName=gname)
            inline_names = resp.get("PolicyNames", []) if ok else []
            inline = []
            for pn in inline_names:
                ok2, resp2 = _safe_call(iam.get_group_policy, GroupName=gname, PolicyName=pn)
                if ok2:
                    inline.append({"name": pn, "document": resp2.get("PolicyDocument")})

            data["groups"].append({
                "group": g,
                "members": members,
                "attached": attached,
                "inline": inline,
            })

    # ---- Roles ----
    role_p = iam.get_paginator("list_roles")
    for page in role_p.paginate():
        for r in page.get("Roles", []):
            rname = r["RoleName"]

            # attached role policies
            ok, resp = _safe_call(iam.list_attached_role_policies, RoleName=rname)
            attached = resp.get("AttachedPolicies", []) if ok else []
            for ap in attached:
                _arn_set_add(managed_policy_arns, ap.get("PolicyArn"))

            # inline role policies
            ok, resp = _safe_call(iam.list_role_policies, RoleName=rname)
            inline_names = resp.get("PolicyNames", []) if ok else []
            inline = []
            for pn in inline_names:
                ok2, resp2 = _safe_call(iam.get_role_policy, RoleName=rname, PolicyName=pn)
                if ok2:
                    inline.append({"name": pn, "document": resp2.get("PolicyDocument")})

            # role tags
            ok, resp = _safe_call(iam.list_role_tags, RoleName=rname)
            tags = resp.get("Tags", []) if ok else []

            data["roles"].append({
                "role": r,
                "trust": r.get("AssumeRolePolicyDocument"),
                "attached": attached,
                "inline": inline,
                "tags": tags,
            })

    # ---- Managed policies ----
    for arn in sorted(managed_policy_arns):
        ok, resp = _safe_call(iam.get_policy, PolicyArn=arn)
        if not ok:
            continue
        pol = resp.get("Policy")
        if not pol:
            continue
        default_ver = pol.get("DefaultVersionId")
        doc = None
        if default_ver:
            ok2, resp2 = _safe_call(iam.get_policy_version, PolicyArn=arn, VersionId=default_ver)
            if ok2:
                doc = (resp2.get("PolicyVersion") or {}).get("Document")
        data["policies"][arn] = {"policy": pol, "document": doc}

    return data
