# Provider: AZURE
# Resource-Type: Azure.SQL.FirewallRule
# Description: SQL Server firewall rules should not permit start and end IP addresses to be 0.0.0.0. Setting start and end IP address to 0.0.0.0 for a SQL firewall rule allows any Azure-internal IP address to access the SQL server. Removing unfettered connectivity to a SQL server reduces the chance of exposing critical data.

deny {
  input.start_ip_address == "0.0.0.0"
  input.end_ip_address == "0.0.0.0"
}