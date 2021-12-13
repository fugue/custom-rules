package rules.k8s_job_check_prod
import data.fugue

__rego__metadoc__ := {
	"title": "Job containers in the prod namespace should not be named `test`",
   "description": "Do not name Job containers `test` if they are in the `prod` namespace",
	"custom": {
     "providers": ["REPOSITORY"],
     "severity": "Low"
  }
}

input_type := "k8s"

resource_type := "Job"

default deny = false

# If any Job container is named `test`, it fails; otherwise it passes
deny {
    input.spec.template.spec.containers[_].name == "test"
}