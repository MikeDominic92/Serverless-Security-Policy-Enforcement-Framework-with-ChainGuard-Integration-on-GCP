# NIST SP 800-53 Compliance Mapping

This document maps our security policies to specific NIST SP 800-53 controls, demonstrating how the framework helps maintain compliance with this security standard.

## Policy to Control Mapping

| Policy File | Resource Type | NIST Control | Control Description | Implementation Details |
|-------------|---------------|--------------|---------------------|------------------------|
| `vm_no_external_ip.rego` | compute.googleapis.com/Instance | SC-7 (Boundary Protection) | Monitors and controls communications at external interfaces to the system. | Checks if VM instances have public IP addresses (ONE_TO_ONE_NAT configurations), which could expose them directly to the internet. |
| `bucket_no_public_access.rego` | storage.googleapis.com/Bucket | AC-3 (Access Enforcement) | Enforces approved authorizations for logical access to information and system resources. | Verifies that Cloud Storage buckets don't grant public read access via IAM bindings to "allUsers" or "allAuthenticatedUsers". |
| `vm_approved_os.rego` | compute.googleapis.com/Instance | CM-7 (Least Functionality) | The organization configures the information system to provide only essential capabilities. | Enforces that VMs use only approved OS images from a pre-defined allow list. |
| `vm_shielded.rego` | compute.googleapis.com/Instance | SI-7 (Software, Firmware, and Information Integrity) | Employs integrity verification tools to detect unauthorized changes to software and firmware. | Ensures VMs are created with Shielded VM features enabled for enhanced security. |
| `vpc_flow_logs.rego` | compute.googleapis.com/Network | AU-12 (Audit Generation) | The system generates audit records containing information specified in AU-3. | Verifies that VPC Flow Logs are enabled for comprehensive network traffic logging. |
| `cloud_armor_waf.rego` | compute.googleapis.com/BackendService | SC-7 (Boundary Protection) | Implements subnetworks for publicly accessible system components. | Checks that internet-facing services use Cloud Armor WAF protection. |
| `kms_rotation.rego` | cloudkms.googleapis.com/CryptoKey | SC-12 (Cryptographic Key Establishment and Management) | Establishes and manages cryptographic keys. | Verifies that KMS keys have automatic rotation enabled. |
| `ChainGuard Integration` | Various with container images | SA-10 (Developer Configuration Management) | The organization requires the developer to maintain the integrity of the systems or components. | Verifies container image signatures and attestations using Sigstore/Cosign to ensure software supply chain integrity. |

## Implementing Additional Controls

To expand coverage of NIST controls, consider implementing these additional policies:

1. **IAM Least Privilege (AC-6)**: Check for overly permissive IAM roles
2. **Logging & Monitoring (AU-2, AU-6)**: Ensure appropriate logging is enabled
3. **Authentication Controls (IA-2)**: Verify MFA enforcement and service account usage
4. **Network Segmentation (SC-7)**: Validate proper VPC network design
5. **Configuration Management (CM-6)**: Check for secure configuration baselines

## Related Documentation

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [GCP Security Foundations Blueprint](https://cloud.google.com/architecture/security-foundations)
- [CIS Google Cloud Computing Foundations Benchmark](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
