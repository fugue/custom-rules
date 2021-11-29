# This rule demonstrates how to check for missing resources,
# using fugue.missing_resource(resource_type)

package rules.requirepasswordpolicy
import data.fugue

__rego__metadoc__ := {
  "title": "AWS accounts require a password policy",
  "description": "All AWS accounts must contain a password policy resource requiring a minimum password length of 16 characters",
  "custom": {
    "providers": ["AWS", "REPOSITORY"],
    "severity": "High"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

password_policies = fugue.resources("aws_iam_account_password_policy")

policy[r] {
  # If a password policy exists and it requires 16+ characters, 
  # return a PASS rule result
  password_policy = password_policies[_]
  password_policy.minimum_password_length >= 16
  r = fugue.allow_resource(password_policy)
} {
  # If a password policy exists but requires less than 16 characters,
  # return a FAIL rule result
  password_policy = password_policies[_]
  not password_policy.minimum_password_length >= 16
  r = fugue.deny_resource(password_policy)
} {
  # If a password policy does not exist, return a FAIL rule result
  count(password_policies) == 0
  r = fugue.missing_resource("aws_iam_account_password_policy")
}