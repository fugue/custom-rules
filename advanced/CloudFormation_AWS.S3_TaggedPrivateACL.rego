# This CloudFormation rule filters out S3 buckets that do not have a
# stage:prod tag. For the Terraform equivalent, see
# custom-rules/advanced/Advanced_AWS.S3_TaggedPrivateACL.rego

package rules.filterbuckets_cfn
import data.fugue

__rego__metadoc__ := {
  "title": "CloudFormation - AWS S3 buckets tagged 'stage:prod' must have private ACLs",
  "description": "S3 buckets with the tag key 'stage' and value 'prod' must have private ACLs",
  "custom": {
    "providers": ["REPOSITORY"],
    "severity": "High"
  }
}

# Note that the input type is set to "cfn" for CloudFormation.
input_type = "cfn"

resource_type = "MULTIPLE"

buckets = fugue.resources("AWS::S3::Bucket")

# If a bucket is tagged stage:prod and its ACL is private, it passes.
# If it's tagged stage:prod and its ACL is NOT private, it fails.
# If it doesn't have a stage:prod tag, it is ignored.
policy[r] {
  bucket = buckets[_]
  bucket.Tags[_].Key == "stage"
  bucket.Tags[_].Value == "prod"
  bucket.AccessControl == "Private"
  r = fugue.allow_resource(bucket)
} {
  bucket = buckets[_]
  bucket.Tags[_].Key == "stage"
  bucket.Tags[_].Value == "prod"
  not bucket.AccessControl == "Private"
  r = fugue.deny_resource(bucket)
}