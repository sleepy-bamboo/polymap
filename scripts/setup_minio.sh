#!/bin/sh
set -eu

MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://localhost:9000}"
MINIO_USER="${MINIO_USER:-minioadmin}"
MINIO_PASS="${MINIO_PASS:-minioadmin}"
SCENARIO_ACCESS_KEY="${SCENARIO_ACCESS_KEY:-scenario3access}"
SCENARIO_SECRET_KEY="${SCENARIO_SECRET_KEY:-scenario3secret}"
DEV_USER_ACCESS_KEY="${DEV_USER_ACCESS_KEY:-dev_user}"
DEV_USER_SECRET_KEY="${DEV_USER_SECRET_KEY:-dev_user_secret}"

mc alias set local "$MINIO_ENDPOINT" "$MINIO_USER" "$MINIO_PASS"

# Create buckets (ignore if they already exist).
mc mb --ignore-existing local/finance-audit
mc mb --ignore-existing local/reports-bucket

# Set tags
mc tag set local/finance-audit "Environment=prod&DataClassification=restricted"
mc tag set local/reports-bucket "Environment=dev"

# Apply bucket policies (MinIO doesn't support AWS Org conditions or ACLs).
cat > /tmp/finance-audit-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "LegacyPublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::finance-audit/legacy/*"
    }
  ]
}
JSON

cat > /tmp/reports-bucket-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadForAll",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::reports-bucket/*"
    }
  ]
}
JSON

mc anonymous set-json /tmp/finance-audit-policy.json local/finance-audit
mc anonymous set-json /tmp/reports-bucket-policy.json local/reports-bucket

# Create a dedicated user with a read-only policy for testing.
cat > /tmp/scenario3-user-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListFinanceAudit",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::finance-audit"]
    },
    {
      "Sid": "ReadFinanceAudit",
      "Effect": "Allow",
      "Action": ["s3:GetObject"],
      "Resource": ["arn:aws:s3:::finance-audit/*"]
    },
    {
      "Sid": "ReadReportsBucket",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:ListBucket"],
      "Resource": [
        "arn:aws:s3:::reports-bucket",
        "arn:aws:s3:::reports-bucket/*"
      ]
    }
  ]
}
JSON

SCENARIO_USER_CREATED=0
if ! mc admin user info local "$SCENARIO_ACCESS_KEY" >/dev/null 2>&1; then
  mc admin user add local "$SCENARIO_ACCESS_KEY" "$SCENARIO_SECRET_KEY"
  SCENARIO_USER_CREATED=1
fi
mc admin policy add local scenario3-user-policy /tmp/scenario3-user-policy.json >/dev/null 2>&1 || true
mc admin policy set local scenario3-user-policy user="$SCENARIO_ACCESS_KEY"

# Add dev_user from IAM scenario 3: list-only for reports-bucket.
cat > /tmp/dev-user-policy.json <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListReportsBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::reports-bucket"
    }
  ]
}
JSON

DEV_USER_CREATED=0
if ! mc admin user info local "$DEV_USER_ACCESS_KEY" >/dev/null 2>&1; then
  mc admin user add local "$DEV_USER_ACCESS_KEY" "$DEV_USER_SECRET_KEY"
  DEV_USER_CREATED=1
fi
mc admin policy add local dev-user-policy /tmp/dev-user-policy.json >/dev/null 2>&1 || true
mc admin policy set local dev-user-policy user="$DEV_USER_ACCESS_KEY"

# Create test objects.
printf '%s\n' "legacy public object" > /tmp/legacy.txt
printf '%s\n' "private object" > /tmp/private.txt
printf '%s\n' "reports public object" > /tmp/report.txt

mc cp /tmp/legacy.txt local/finance-audit/legacy/readme.txt
mc cp /tmp/private.txt local/finance-audit/private/secret.txt
mc cp /tmp/report.txt local/reports-bucket/report1.txt

# Verify access by URL (public vs private).
if command -v curl >/dev/null 2>&1; then
  echo "Checking public URL access..."
  curl -s -o /dev/null -w "finance-audit legacy: %{http_code}\n" \
    "$MINIO_ENDPOINT/finance-audit/legacy/readme.txt"
  curl -s -o /dev/null -w "finance-audit private: %{http_code}\n" \
    "$MINIO_ENDPOINT/finance-audit/private/secret.txt"
  curl -s -o /dev/null -w "reports-bucket public: %{http_code}\n" \
    "$MINIO_ENDPOINT/reports-bucket/report1.txt"
else
  echo "curl not found; skipping URL checks."
fi

echo "MinIO scenario 3 setup complete."
echo "Access key: $SCENARIO_ACCESS_KEY"
if [ "$SCENARIO_USER_CREATED" -eq 1 ]; then
  echo "Secret key: $SCENARIO_SECRET_KEY"
else
  echo "Secret key: <unchanged from existing user>"
fi
echo "Dev user access key: $DEV_USER_ACCESS_KEY"
if [ "$DEV_USER_CREATED" -eq 1 ]; then
  echo "Dev user secret key: $DEV_USER_SECRET_KEY"
else
  echo "Dev user secret key: <unchanged from existing user>"
fi
