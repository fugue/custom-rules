# This rule demonstrates checking for a missing resource with
# fugue.missing_resource(resource_type)

package rules.google_default_audit_log_config
import data.fugue

__rego__metadoc__ := {
  "title": "Google projects should have a default audit log config",
  "description": "All Google projects are required to have a default audit log configuration",
  "custom": {
    "providers": ["GOOGLE"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

configs = fugue.resources("Google.ResourceManager.ProjectIAMAuditConfig")

# If a default audit log config exists in an environment, return a
# PASS rule result; if none exist, return a FAIL rule result
policy[r] {
  config = configs[_]
  r = fugue.allow_resource(config)
} {
  count(configs) == 0
  r = fugue.missing_resource("Google.ResourceManager.ProjectIAMAuditConfig")
}