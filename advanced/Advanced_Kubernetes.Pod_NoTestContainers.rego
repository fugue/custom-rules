# This rule filters out Jobs that are not in the prod namespace

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

resource_type := "MULTIPLE"

jobs = fugue.resources("Job")

# If a Job is in the prod namespace and no containers are named
# `test`, it passes. If a Job is in the prod namespace and any
# containers are named `test`, it fails. If a Job is not in the prod
# namespace, it's ignored.
policy[r] {
  job = jobs[_]
  job.metadata.namespace == "prod"
  job.spec.template.spec.containers[_].name != "test" 
  r = fugue.allow_resource(job)
} {
  job = jobs[_]
  job.metadata.namespace == "prod"
  job.spec.template.spec.containers[_].name == "test" 
  r = fugue.deny_resource(job)
}