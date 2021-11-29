package rules.sql_server_firewall_rules

__rego__metadoc__ := {
  "title": "Azure.SQL.FirewallRule-Deny-Azure-services-from-accessing-server",
  "description": "SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0. Setting start and end IP address to 0.0.0.0 for a SQL firewall rule allows any Azure-internal IP address to access the SQL server. Removing unfettered connectivity to a SQL server reduces the chance of exposing critical data.",
  "custom": {
    "providers": ["AZURE"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "Azure.SQL.FirewallRule"

default deny = false

# If start and end IP address are both 0.0.0.0/0, the resource fails; otherwise it passes
deny {
  input.start_ip_address == "0.0.0.0"
  input.end_ip_address == "0.0.0.0"
}