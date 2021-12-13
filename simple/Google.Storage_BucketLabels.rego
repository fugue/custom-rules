package rules.storage_bucket_labels

__rego__metadoc__ := {
  "title": "Google storage buckets must be labeled stage:prod",
  "description": "Google storage buckets are required to have stage:prod labels",
  "custom": {
    "severity": "Medium",
    "providers": ["GOOGLE"]
  }
}

resource_type = "Google.Storage.Bucket"

default allow = false

# If the storage bucket is labeled stage:prod, it passes; otherwise
# it fails
allow {
  input.labels.stage == "prod"
}