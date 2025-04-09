# File: bucket_no_public_access.rego
package gcp.storage.bucket.public_access

# Default: Allow (no violation)
default deny = false

# Violation if 'allUsers' or 'allAuthenticatedUsers' have reader roles
deny {
    some binding in input.iamConfiguration.bindings
    is_public_member(binding.members)
    is_reader_role(binding.role)
}

is_public_member(members) {
    members[_] == "allUsers"
}

is_public_member(members) {
    members[_] == "allAuthenticatedUsers"
}

is_reader_role(role) = true {
    role == "roles/storage.objectViewer"
}

is_reader_role(role) = true {
    role == "roles/storage.legacyObjectReader"
}

# Message describing the violation
message = "Storage buckets should not grant 'allUsers' or 'allAuthenticatedUsers' read access."

# Rule structure for easier consumption by the function
violation[{"policy_id": "bucket_public_access", "message": message, "metadata": {"severity": "HIGH", "compliance": ["NIST-SC-7"]}}] {
    deny
}
