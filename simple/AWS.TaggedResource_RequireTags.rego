# Provider: AWS
# Resource-Type: AWS.S3.Bucket
# Description: For AWS resources that support tags, require a tag named Stage with a value Prod. 

# This example checks AWS.S3.Bucket resources, but you can
# substitute another taggable resource in the line above. See 
# https://docs.fugue.co/servicecoverage.html for formatting.

allow {
  input.tags.Stage == "Prod"
}
