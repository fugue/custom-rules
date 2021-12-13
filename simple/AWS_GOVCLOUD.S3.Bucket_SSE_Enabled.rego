package rules.bucket_sse_encryption

__rego__metadoc__ := {
  "title": "AWS-GOVCLOUD.S3.Bucket-SSE-Enabled",
  "description": "SSE encryption should be enabled for S3 buckets (AES-256 or KMS).",
  "custom": {
    "providers": ["AWS_GOVCLOUD"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "AWS.S3.Bucket"

default allow = false

# If SSE encryption is enabled for a bucket, it passes; otherwise
# it fails
allow {
  input.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm = _
}