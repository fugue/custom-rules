package rules.require_tags_simple

__rego__metadoc__ := {
  "title": "AWS.TaggedResource-RequireTags",
  "description": "For AWS resources that support tags, require a tag named Stage with a value Prod.",
  "custom": {
    "providers": ["AWS"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "AWS.S3.Bucket"

# This example checks AWS.S3.Bucket resources, but you can
# substitute another taggable resource in the line above. See 
# https://docs.fugue.co/servicecoverage.html for formatting.

default allow = false

# If a bucket is tagged Stage:Prod, it passes; otherwise it fails
allow {
  input.tags.Stage == "Prod"
}
