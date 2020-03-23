# Provider: AWS
# Resource-Type: AWS.EC2.SecurityGroup
# Description: VPC security groups should not permit ingress from '0.0.0.0/0' to TCP port 9200 (Elasticsearch). Removing unfettered connectivity to an Elasticsearch server reduces the chance of exposing critical data.

deny {
  input.ingress[i].from_port <= 9200
  input.ingress[i].to_port >= 9200
  input.ingress[i].cidr_blocks[_] == "0.0.0.0/0"
}
