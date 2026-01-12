from __future__ import annotations

import json
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

def make_session(profile: str | None, region: str):
    cfg = Config(
        retries={"max_attempts": 10, "mode": "standard"},
        connect_timeout=5,
        read_timeout=30,
        region_name=region,
    )
    if profile:
        return boto3.Session(profile_name=profile, region_name=region), cfg
    return boto3.Session(region_name=region), cfg

def _get_bucket_tags(s3, name: str):
    try:
        resp = s3.get_bucket_tagging(Bucket=name)
        return resp.get("TagSet", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchTagSet", "NoSuchBucket", "AccessDenied"):
            return []
        raise

def _get_public_access_block(s3, name: str):
    try:
        return s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchPublicAccessBlockConfiguration", "AccessDenied", "NoSuchBucket"):
            return None
        raise

def collect_s3(session_and_cfg):
    session, cfg = session_and_cfg
    s3 = session.client("s3", config=cfg)

    out = {"buckets": []}
    buckets = s3.list_buckets()["Buckets"]

    for b in buckets:
        name = b["Name"]
        bucket = {
            "name": name,
            "created": b["CreationDate"],
            "tags": _get_bucket_tags(s3, name),
            "public_access_block": _get_public_access_block(s3, name),
            "policy": None,
            "acl": None,
        }

        # bucket policy
        try:
            p = s3.get_bucket_policy(Bucket=name)["Policy"]
            bucket["policy"] = json.loads(p)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("NoSuchBucketPolicy", "AccessDenied", "NoSuchBucket"):
                raise

        # ACL
        try:
            bucket["acl"] = s3.get_bucket_acl(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDenied", "NoSuchBucket"):
                raise

        out["buckets"].append(bucket)

    return out
