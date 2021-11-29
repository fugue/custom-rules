# This simple rule is rewritten as an advanced rule in 
# custom-rules/advanced/Advanced_AWS.EC2.SecurityGroup_NoIngressPort9200.rego.

package rules.sg_no_ingress_9200

__rego__metadoc__ := {
  "title": "AWS.EC2.SecurityGroup-NoIngressPort9200",
  "description": "VPC security groups should not permit ingress from '0.0.0.0/0' to TCP port 9200 (Elasticsearch). Removing unfettered connectivity to an Elasticsearch server reduces the chance of exposing critical data.",
  "custom": {
    "providers": ["AWS"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "AWS.EC2.SecurityGroup"

default deny = false

# Security groups that have port 9200 open to the internet are considered invalid
deny {
  input.ingress[i].from_port <= 9200
  input.ingress[i].to_port >= 9200
  input.ingress[i].cidr_blocks[_] == "0.0.0.0/0"
}
