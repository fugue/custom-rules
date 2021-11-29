package rules.require_availability_set

__rego__metadoc__ := {
  "title": "Azure.Compute.VirtualMachine-RequireAvailabilitySet",
  "description": "Virtual Machine instances should be assigned to availability sets. Deploying VMs in availability sets promotes redundancy of data.",
  "custom": {
    "providers": ["AZURE"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "Azure.Compute.VirtualMachine"

default allow = false

# If a VM has an availability set ID, it passes; otherwise it fails
allow {
  startswith(input.availability_set_id, "/")
}
