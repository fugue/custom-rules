package rules.managed_iam_policy_description

__rego__metadoc__ := {
  "title": "CloudFormation - IAM policies must have a description of at least 25 characters",
  "description": "Per company policy, it is required for all IAM policies to have a description of at least 25 characters.",
  "custom": {
    "providers": ["REPOSITORY"],
    "severity": "Low"
  }
}

input_type := "cfn"

resource_type = "AWS::IAM::ManagedPolicy"

default allow = false

# If the description is 25+ characters, the policy passes; otherwise
# it fails
allow {
  count(input.Description) >= 25
}