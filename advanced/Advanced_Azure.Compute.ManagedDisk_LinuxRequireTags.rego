package rules.managed_disks_linux_tags
import data.fugue

__rego__metadoc__ := {
  "title": "Advanced-Azure.Compute.ManagedDisk-LinuxRequireTags",
  "description": "Azure managed disks running Linux must have \"application\" tag",
  "custom": {
    "providers": ["AZURE"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

# The following advanced custom rule checks that all managed disks running 
# Linux have an "application" tag with a non-blank value. Because this is 
# an advanced custom rule, select "MULTIPLE" from the Resource Type 
# dropdown on the Fugue Custom Rules page.
#
# This is an advanced rule because it validates Linux managed disks only;
# it can be written as a simple rule if you want to validate all managed disks.

# All managed disks in the env
managed_disks = fugue.resources("Azure.Compute.ManagedDisk")

# Valid disks have the tag key "application" and a value that isn't an empty string
valid(disk) {
  disk.tags.application != ""
}

# Each managed disk running Linux passes if it has an application tag and fails if it does not
policy[r] {
   managed_disk = managed_disks[_]
   managed_disk.os_type == "Linux"
   valid(managed_disk) 
   r = fugue.allow_resource(managed_disk)
} {
   managed_disk = managed_disks[_]
   managed_disk.os_type == "Linux"
   not valid(managed_disk) 
   r = fugue.deny_resource(managed_disk)
}