# Provider: AWS_GOVCLOUD
# Resource-Type: AWS.S3.Bucket
# Description: SSE encryption should be enabled for S3 buckets (AES-256 or KMS).

allow {
  input.server_side_encryption_configuration[_].rule[_][_][_].sse_algorithm = _
}