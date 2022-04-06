package rules.all_taggable_resources_multicloud
import data.fugue

__rego__metadoc__ := {
  "title": "All storage must be tagged environment:staging",
  "description": "AWS, Azure, and Google storage resources should be tagged with environment:staging in both runtime and IaC",
  "custom": {
    "providers": ["AWS", "AZURE", "GOOGLE", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

# The following multi-resource type validation checks AWS S3 buckets,
# Azure storage accounts, and Google storage buckets (in runtime AND
# infrastructure as code) for a tag named "environment" with the value
# "staging"

taggable_resource_types = {
  "aws_s3_bucket",
  "azurerm_storage_account",
  "google_storage_bucket"
}

scanned_resource_types = fugue.input_resource_types

# For each taggable resource type, add each of its resources 
# to the taggable_resources collection
taggable_resources[id] = resource {
  some type_name
  type_name = scanned_resource_types[_]
  taggable_resource_types[type_name]
  resources = fugue.resources(type_name)
  resource = resources[id]
}

# Check if resource is properly tagged (AWS, Azure) or labeled
# (Google) with environment:staging
is_properly_tagged(resource) {
  resource.tags.environment == "staging"
} {
  resource.labels.environment == "staging"
}

# If the resource is properly tagged, return a PASS rule result;
# otherwise, a FAIL rule result
policy[r] {
   resource = taggable_resources[_]
   is_properly_tagged(resource)
   r = fugue.allow_resource(resource)
} {
   resource = taggable_resources[_]
   not is_properly_tagged(resource)
   r = fugue.deny_resource(resource)
}