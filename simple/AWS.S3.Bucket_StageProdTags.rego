package rules.buckettags

__rego__metadoc__ := {
  "title": "AWS S3 buckets must be tagged",
  "description": "S3 buckets must have the tag key 'stage' and value 'prod'",
  "custom": {
    "providers": ["AWS", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "aws_s3_bucket"

default allow = false

# If a bucket is tagged stage:prod, it passes; otherwise it fails
allow {
  input.tags.stage == "prod"
}