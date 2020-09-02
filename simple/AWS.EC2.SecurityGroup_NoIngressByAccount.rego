# Provider: AWS
# Resource-Type: AWS.EC2.SecurityGroup
# Description: The Production account can only allow ingress from 0.0.0.0/0 to port 443.  Other accounts may allow ingress to port 80.

# This is an example of a more complex rule.  It does a whitelist check on
# ingress ports in security groups; however, the whitelist of ports is
# determined by AWS account number.

# The account ID.
account_id = ret {
  # Split "arn:aws:ec2:REGION:ACCOUNT_ID:security-group/RESOURCE_ID" to
  # obtain the account ID this resource belongs to.
  parts = split(input.arn, ":")
  ret = parts[4]
}

# Build a set of allowed ports.  This depends on the account ID.

# Port 443 is always allowed.
allowed_ports[443] {
  true
}

# Port 80 is not allowed in the production account.
allowed_ports[80] {
  account_id != "000000000000"  # Production, replace this.
}

# You can add more logic for further `allowed_ports` here.
# allowed_ports[8080] {
#   account_id == "111111111111"  # Staging
# }

# Check if an ingress block allows ingress from anywhere.
ingress_cidr_wildcard(ingress) {
  ingress.cidr_blocks[_] == "0.0.0.0/0"
} {
  ingress.ipv6_cidr_blocks[_] == "::/0"
}

# Check if an ingress block is valid.  It is valid if either:
# 1. It does not allow ingress from 0.0.0.0/0
# 2. It allows ingress from a specific port which is in `allowed_ports`
valid_ingress(ingress) {
  not ingress_cidr_wildcard(ingress)
} {
  ingress.from_port == ingress.to_port
  allowed_ports[_] == ingress.from_port
}

# A security group has a list of ingress blocks.  We want to deny the
# resource if _any_ of the ingress blocks is not valid.
default deny = false
deny {
  ingress = input.ingress[_]
  not valid_ingress(ingress)
}
