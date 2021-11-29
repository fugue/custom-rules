# Provider: AWS
# Resource-Type: MULTIPLE
# Description: The following multi-resource type validation checks that all Security Groups attached to the production VPC have a Stage tag with the value Prod.
#
# The production VPC.
prod_vpc = vpc {
  vpcs = fugue.resources("AWS.EC2.Vpc")
  vpc = vpcs[_]
  vpc.tags.Name == "prod-vpc"
}
# Security groups attached to the prod VPC.
prod_security_groups[id] = security_group {
  security_groups = fugue.resources("AWS.EC2.SecurityGroup")
  security_group = security_groups[id]
  security_group.vpc_id == prod_vpc.id
}
# Check that the security group is tagged with {"Stage": "Prod"}.
tagged_security_group(security_group) {
  security_group.tags.Stage == "Prod"
}
# Build policy document.
policy[p] {
  security_group = prod_security_groups[_]
  tagged_security_group(security_group)
  p = fugue.allow_resource(security_group)
} {
  security_group = prod_security_groups[_]
  not tagged_security_group(security_group)
  p = fugue.deny_resource(security_group)
}