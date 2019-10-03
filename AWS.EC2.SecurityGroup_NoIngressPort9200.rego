deny {
  input.ingress[i].from_port <= 9200
  input.ingress[i].to_port >= 9200
  input.ingress[i].cidr_blocks[_] == "0.0.0.0/0"
}
