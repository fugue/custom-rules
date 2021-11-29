# This rule demonstrates how to return a parameterized noncompliance
# message using fugue.deny_resource_with_message(resource_type, msg)

package rules.azure_log_profile_delete_category
import data.fugue

__rego__metadoc__ := {
  "title": "Azure log profiles must log Delete category",
  "description": "An Azure log profile must exist and it must log the category Delete",
  "custom": {
    "providers": ["AZURE", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

log_profiles = fugue.resources("azurerm_monitor_log_profile")

# Check if a log profile has the Delete category
has_delete_category(log_profile) {
  log_profile.categories[_] == "Delete"
}

# If no log profile exists, return a FAIL result and custom message
policy[r] {
  count(log_profiles) == 0
  msg = "Required log profile is missing."
  r = fugue.missing_resource_with_message("azurerm_monitor_log_profile", msg)
} {
  # If a log profile exists and logs the Delete category, return a PASS
  # rule result
  log_profile = log_profiles[_]
  has_delete_category(log_profile)
  r = fugue.allow_resource(log_profile)
} {
  # If a log profile exists but does not log the Delete category,
  # return a FAIL rule result and a message listing the categories it
  # DOES log
  log_profile = log_profiles[_]
  not has_delete_category(log_profile)
  msg = sprintf("Log profile does not log the 'Delete' category. It logs these categories: %s", [concat(", ", log_profile.categories)])
  r = fugue.deny_resource_with_message(log_profile, msg)
}