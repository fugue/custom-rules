package rules.google_bucket_versioning

__rego__metadoc__ := {
  "title": "Google storage buckets should have versioning enabled",
  "description": "Object versioning protects data from being overwritten or unintentionally deleted",
  "custom": {
    "providers": ["GOOGLE", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "google_storage_bucket"

default allow = false

# If bucket versioning is enabled, the bucket passes; otherwise it fails
allow {
  input.versioning[_].enabled == true
}