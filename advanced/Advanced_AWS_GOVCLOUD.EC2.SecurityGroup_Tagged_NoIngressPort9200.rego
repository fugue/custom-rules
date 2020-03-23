# Provider: AWS_GOVCLOUD
# Resource-Type: MULTIPLE
# Description: VPC security groups tagged Stage:Prod should not permit ingress from '0.0.0.0/0' to TCP port 9200 (Elasticsearch). Removing unfettered connectivity to an Elasticsearch server reduces the chance of exposing critical data.

# Return all security groups in an environment, then filter on the tag Stage:Prod
tagged_sgs[tags] = security_group {
   security_groups = fugue.resources("AWS.EC2.SecurityGroup")
   security_group = security_groups[tags]
   security_group.tags.Stage == "Prod"
}

# Security groups that have port 9200 open to the internet are considered invalid
invalid(sg) {
  sg.ingress[i].from_port <= 9200
  sg.ingress[i].to_port >= 9200
  sg.ingress[i].cidr_blocks[_] == "0.0.0.0/0"   
}

# Build policy document; of the security groups tagged Stage:Prod, invalid SGs fail, valid ones pass
policy[r] {
   security_group = tagged_sgs[_]
   invalid(security_group)
   r = fugue.deny_resource(security_group)
} {
   security_group = tagged_sgs[_]
   not invalid(security_group)
   r = fugue.allow_resource(security_group)
}