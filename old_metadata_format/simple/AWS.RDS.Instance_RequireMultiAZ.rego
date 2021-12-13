# Provider: AWS
# Resource-Type: AWS.RDS.Instance
# Description: RDS instance multi-AZ should be enabled. An RDS instance in a Multi-AZ (availability zone) deployment provides enhanced availability and durability of data.

allow {
  input.multi_az == true
}
