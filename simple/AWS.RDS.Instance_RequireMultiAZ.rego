package rules.multi_az_enabled

__rego__metadoc__ := {
  "title": "AWS.RDS.Instance-RequireMultiAZ",
  "description": "RDS instance multi-AZ should be enabled. An RDS instance in a Multi-AZ (availability zone) deployment provides enhanced availability and durability of data.",
  "custom": {
    "providers": ["AWS"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "AWS.RDS.Instance"

default allow = false

# If multi-AZ is enabled, the resource passes; otherwise it fails
allow {
  input.multi_az == true
}
