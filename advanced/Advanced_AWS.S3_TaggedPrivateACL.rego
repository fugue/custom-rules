# This Terraform rule filters out S3 buckets that do not have a
# stage:prod tag. For the CloudFormation equivalent, see
# custom-rules/advanced/CloudFormation_AWS.S3_TaggedPrivateACL.rego

package rules.filterbuckets
import data.fugue

__rego__metadoc__ := {
  "title": "AWS S3 buckets tagged 'stage:prod' must have private ACLs",
  "description": "S3 buckets with the tag key 'stage' and value 'prod' must have private ACLs",
  "custom": {
    "providers": ["AWS", "REPOSITORY"],
    "severity": "High"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

buckets = fugue.resources("aws_s3_bucket")

# If a bucket is tagged stage:prod and its ACL is private, it passes.
# If it's tagged stage:prod and its ACL is NOT private, it fails.
# If it doesn't have a stage:prod tag, it is ignored.
policy[r] {
  bucket = buckets[_]
  bucket.tags.stage == "prod"
  bucket.acl == "private"
  r = fugue.allow_resource(bucket)
} {
  bucket = buckets[_]
  bucket.tags.stage == "prod"
  not bucket.acl == "private"
  r = fugue.deny_resource(bucket)
}