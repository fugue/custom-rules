# Azure.Compute.VirtualMachine
# Virtual Machines instances should be assigned to availability sets. Deploying VMs in availability sets promotes redundancy of data.

allow {
  startswith(input.availability_set_id, "/")
}
