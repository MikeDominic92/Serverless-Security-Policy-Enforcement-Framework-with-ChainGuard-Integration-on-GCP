# File: vm_no_external_ip.rego
package gcp.compute.vm.external_ip

# Default: Allow (no violation)
default deny = false

# Violation if any network interface has an access config of type ONE_TO_ONE_NAT
deny {
    some i
    input.networkInterfaces[i].accessConfigs[_].type == "ONE_TO_ONE_NAT"
}

# Message describing the violation
message = "VM instances should not have external IP addresses assigned."

# Rule structure for easier consumption by the function
violation[{"policy_id": "vm_external_ip", "message": message, "metadata": {"severity": "HIGH"}}] {
    deny
}
