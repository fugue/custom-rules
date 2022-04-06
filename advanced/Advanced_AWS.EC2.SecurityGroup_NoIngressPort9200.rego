# This is an advanced version of a simple rule. It can be rewritten 
# as the simple rule in 
# custom-rules/simple/AWS.EC2.SecurityGroup_NoIngressPort9200.rego.

package rules.sg_9200
import data.fugue

__rego__metadoc__ := {
  "title": "Advanced-AWS.EC2.SecurityGroup-NoIngressPort9200",
  "description": "VPC security groups should not permit ingress from '0.0.0.0/0' to TCP port 9200 (Elasticsearch). Removing unfettered connectivity to an Elasticsearch server reduces the chance of exposing critical data.",
  "custom": {
    "providers": ["AWS"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

# Return all security groups in an environment
security_groups = fugue.resources("AWS.EC2.SecurityGroup")

# Security groups that have port 9200 open to the internet are considered invalid
invalid(sg) {
  sg.ingress[i].from_port <= 9200
  sg.ingress[i].to_port >= 9200
  sg.ingress[i].cidr_blocks[_] == "0.0.0.0/0"   
}

# Build policy document; invalid security groups fail, valid ones pass
policy[r] {
   security_group = security_groups[_]
   invalid(security_group) 
   r = fugue.deny_resource(security_group)
} {
   security_group = security_groups[_]
   not invalid(security_group)
   r = fugue.allow_resource(security_group)
}