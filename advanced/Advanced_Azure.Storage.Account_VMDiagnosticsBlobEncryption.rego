# This rule checks two resource types:
# Azure storage accounts and VMs.

package rules.azure_storage_vms
import data.fugue

__rego__metadoc__ := {
  "title": "Encrypt VM boot diagnostics in storage accounts",
  "description": "Azure storage accounts used to store virtual machine boot diagnostics should have blob encryption enabled",
  "custom": {
    "providers": ["AZURE"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

storage_accts = fugue.resources("Azure.Storage.Account")
vms = fugue.resources("Azure.Compute.VirtualMachine")

# Collect all of the storage account endpoints holding VM diagnostics
vm_stor_uris[stor_uri] {
  stor_uri = vms[_].boot_diagnostics[_].storage_uri
}

# Check each storage account holding VM diagnostics; if it has blob
# encryption enabled, it passes; otherwise it fails
policy[r] {
  storage_acct = storage_accts[_]
  vm_stor_uris[storage_acct.primary_blob_endpoint]
  storage_acct.enable_blob_encryption == true
  r = fugue.allow_resource(storage_acct)
} {
  storage_acct = storage_accts[_]
  vm_stor_uris[storage_acct.primary_blob_endpoint]
  not storage_acct.enable_blob_encryption == true
  r = fugue.deny_resource(storage_acct)
}