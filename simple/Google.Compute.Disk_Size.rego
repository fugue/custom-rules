package rules.disk_size

__rego__metadoc__ := {
  "title": "Persistent disk size must be 50 to 100 GB",
  "description": "Google persistent disks must be between 50 and 100 GB in size",
  "custom": {
    "providers": ["GOOGLE", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "google_compute_disk"

default allow = false

# If the disk size is between 50 and 100 GB (inclusive), it passes;
# otherwise it fails
allow {
  input.size >= 50
  input.size <= 100
}