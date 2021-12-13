# This rule demonstrates checking multiple resource types:
# Google storage buckets, and storage bucket ACLs

package rules.website_bucket_access_control
import data.fugue

__rego__metadoc__ := {
  "title": "Only Google storage buckets tagged application:website may have a public ACL",
  "description": "Google storage buckets may not have ACLs that allow the allUsers or allAuthenticatedUsers entities to have the READER role unless the bucket is tagged application:website. Buckets without ACLs will pass this rule.",
  "custom": {
    "providers": ["GOOGLE", "REPOSITORY"],
    "severity": "Medium"
  }
}

input_type = "tf"

resource_type = "MULTIPLE"

buckets = fugue.resources("google_storage_bucket")
acls = fugue.resources("google_storage_bucket_acl")

# Collect each of the bucket ACLs, with the associated bucket name
# as the key
acls_by_bucket_name = { bucket_name : acl |
  acl = acls[_]
  bucket_name = acl.bucket
}

# Check the ACL associated with a bucket and see if it's
# READER:allUsers or READER:allAuthenticatedUsers
has_public_acl(bucket) {
  acl = acls_by_bucket_name[bucket.name]
  acl.role_entity[_] == "READER:allUsers"
} {
  acl = acls_by_bucket_name[bucket.name]
  acl.role_entity[_] == "READER:allAuthenticatedUsers"
}

# Check if the bucket is labeled application:website
is_website_bucket(bucket) {
  bucket.labels.application == "website"
}

# A bucket is invalid if it has a public ACL and is not tagged
# application:website
is_invalid(bucket) {
  has_public_acl(bucket)
  not is_website_bucket(bucket)
}

# If a bucket is not invalid, it passes; if it's invalid, it fails
policy[r] {
  bucket = buckets[_]
  not is_invalid(bucket)
  r = fugue.allow_resource(bucket)
} {
  bucket = buckets[_]
  is_invalid(bucket)
  r = fugue.deny_resource(bucket)
}