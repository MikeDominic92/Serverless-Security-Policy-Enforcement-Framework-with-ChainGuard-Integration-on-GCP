# File: vm_shielded.rego
package gcp.compute.vm.shielded

# Default: Allow (no violation)
default deny = false

# Violation if shieldedInstanceConfig is missing or has security features disabled
deny {
    not input.shieldedInstanceConfig
}

deny {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableSecureBoot
}

deny {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableVtpm
}

deny {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableIntegrityMonitoring
}

# Message describing the violation
message = get_message

get_message = msg {
    not input.shieldedInstanceConfig
    msg = "VM is missing shieldedInstanceConfig settings entirely."
}

get_message = msg {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableSecureBoot
    msg = "Secure Boot is not enabled on this VM instance."
}

get_message = msg {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableVtpm
    msg = "Virtual Trusted Platform Module (vTPM) is not enabled on this VM instance."
}

get_message = msg {
    input.shieldedInstanceConfig
    not input.shieldedInstanceConfig.enableIntegrityMonitoring
    msg = "Integrity Monitoring is not enabled on this VM instance."
}

# Rule structure for easier consumption by the function
violation[{"policy_id": "vm_shielded_instance", "message": message, "metadata": metadata}] {
    deny
    metadata = {
        "severity": "HIGH",
        "compliance": ["NIST-SI-7", "CIS-GCP-4.8"],
        "description": "Shielded VM provides verifiable integrity to prevent boot-level and kernel-level malware and rootkits",
        "remediation": "Enable Shielded VM options (Secure Boot, vTPM, and Integrity Monitoring) when creating or updating VM instances"
    }
}
