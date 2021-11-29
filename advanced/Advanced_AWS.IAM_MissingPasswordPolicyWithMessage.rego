# This rule demonstrates how to check for missing resources and return
# a custom noncompliance message on failed and missing resources

package rules.passwordpolicymessage
import data.fugue

__rego__metadoc__ := {
  "title": "AWS accounts require a password policy - message example",
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
  # return a FAIL rule result with message
  password_policy = password_policies[_]
  not password_policy.minimum_password_length >= 16
  msg = "Password policy is too short. It must be at least 16 characters."
  r = fugue.deny_resource_with_message(password_policy, msg)
} {
  # If a password policy does not exist, return a FAIL rule result
  # with message
  count(password_policies) == 0
  msg = "No password policy exists."
  r = fugue.missing_resource_with_message("aws_iam_account_password_policy", msg)
}