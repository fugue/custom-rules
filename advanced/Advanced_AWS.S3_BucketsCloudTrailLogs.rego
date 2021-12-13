# This rule checks two resource types:
# AWS CloudTrail trails and S3 buckets.

package rules.trailbucketlogs
import data.fugue

__rego__metadoc__ := {
  "title": "S3 buckets containing CloudTrail logs must be private",
  "description": "Amazon S3 buckets containing CloudTrail logs must have a private ACL",
  "custom": {
    "providers": ["AWS", "REPOSITORY"],
    "severity": "High"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

trails = fugue.resources("aws_cloudtrail")
buckets = fugue.resources("aws_s3_bucket")

# Collect all the names of buckets containing CloudTrail logs
trail_bucket_ids[bucket] {
  bucket = trails[_].s3_bucket_name
}

# If a bucket is in the trail_bucket_ids collection, and its ACL
# is private, it passes; otherwise it fails. Buckets that do not
# contain CloudTrail logs are ignored.
policy[r] {
  bucket = buckets[_]
  trail_bucket_ids[bucket.bucket]
  bucket.acl == "private"
  r = fugue.allow_resource(bucket)
} {
  bucket = buckets[_]
  trail_bucket_ids[bucket.bucket]
  not bucket.acl == "private"
  r = fugue.deny_resource(bucket)
}