# Serverless Security Policy Enforcement Framework with ChainGuard Integration

A comprehensive serverless framework for Google Cloud Platform (GCP) that automatically enforces security policies across cloud resources with real-time detection and remediation capabilities. This framework integrates ChainGuard/Sigstore for container image supply chain verification, ensuring end-to-end security from development to deployment.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GCP: Serverless](https://img.shields.io/badge/GCP-Serverless-blue)](https://cloud.google.com/serverless)
[![Security: NIST](https://img.shields.io/badge/Security-NIST--800--53-red)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)

## Project Purpose & Industry Context

Modern cloud environments demand proactive, automated security controls that scale with infrastructure. This framework solves critical challenges facing enterprise cloud security teams:

- **Continuous Security Posture**: Traditional point-in-time security reviews are no longer sufficient. This framework provides real-time, continuous monitoring and enforcement of security controls.

- **Supply Chain Security**: With the rise of software supply chain attacks (like SolarWinds and Log4j), organizations must verify the integrity and provenance of container images. The ChainGuard/Sigstore integration addresses this by verifying signatures and attestations.

- **Compliance Automation**: Manual compliance verification is error-prone and costly. This framework maps security policies directly to NIST SP 800-53 controls, providing automated compliance evidence generation.

- **Shift-Left Security**: By integrating with CI/CD pipelines, this framework enables security policy testing before production deployment, catching violations earlier in the development lifecycle.

## Architecture Overview

This framework implements a sophisticated event-driven architecture on Google Cloud Platform:

1. **Cloud Functions (Gen 2)**: Serverless runtime that hosts the core policy evaluation and enforcement logic, scaling automatically with demand

2. **Eventarc & Cloud Audit Logs**: Captures resource creation/modification events in real-time, triggering policy evaluation without polling or scheduled tasks

3. **Cloud Asset Inventory API**: Retrieves comprehensive resource configurations for deep inspection beyond event payload data

4. **Open Policy Agent (OPA) & Rego**: Implements a declarative policy language for expressing complex security rules independent of enforcement logic

5. **ChainGuard/Sigstore Integration**: Verifies container image signatures and attestations using industry-standard tooling (Cosign) for supply chain security

6. **Pub/Sub Message Bus**: Handles asynchronous notification delivery for security violations with guaranteed at-least-once delivery

7. **IAM Service Accounts**: Implements least-privilege permissions for all components, following security best practices

![Architecture Diagram](https://i.imgur.com/1RszX2s.png)

## Technical Implementation

### Directory Structure

```bash
security_enforcement_framework/
├── deployment/                        # Deployment automation
│   └── setup.sh                      # GCP environment setup script
├── docs/                             # Documentation
│   └── nist_compliance_mapping.md    # NIST SP 800-53 control mapping
└── src/
    └── policy_handler/
        ├── main.py                   # Core Cloud Function logic
        ├── requirements.txt          # Python dependencies
        ├── test_policy.py            # Policy testing framework
        ├── policies/                 # Rego policy directory
        │   └── gcp/                  # GCP-specific policies
        │       ├── compute/          # Compute Engine policies
        │       │   └── Instance/     # VM instance policies
        │       │       ├── vm_no_external_ip.rego
        │       │       └── vm_shielded.rego
        │       └── storage/          # Storage policies
        │           └── Bucket/       # Bucket policies
        │               └── bucket_no_public_access.rego
        └── samples/                  # Test samples
            ├── vm_external_ip.json
            ├── vm_no_external_ip.json
            ├── vm_not_shielded.json
            ├── vm_shielded.json
            ├── bucket_private.json
            └── bucket_public.json
```

### Policy Enforcement Core

The `main.py` implements several sophisticated components working together:

1. **Event Handling System**: Processes Cloud Audit Log events from Pub/Sub messages, decoding and validating the payload structure.

2. **Resource Configuration API**: Leverages Cloud Asset Inventory API to fetch comprehensive resource configurations beyond what's available in event payloads.

3. **Policy Evaluation Engine**: Integrates with Open Policy Agent to evaluate resource configurations against Rego policies, handling complex pattern matching and rule evaluation.

4. **ChainGuard Integration**: Implements container image verification using Sigstore's Cosign tool, validating signatures and attestations according to configurable verification parameters.

5. **Remediation Actions**: Provides capability to automatically remediate certain violations (e.g., removing public access from buckets) based on policy findings.

6. **Notification System**: Delivers detailed violation reports through Pub/Sub, enabling integration with SIEM systems, ticketing tools, or custom notification workflows.

### Policy Examples

The framework includes production-ready policies implementing security best practices:

1. **VM External IP Protection** (`vm_no_external_ip.rego`)
   - Prevents exposing VMs directly to the internet with public IP addresses
   - Implements NIST SC-7 (Boundary Protection) controls
   - Examines network interface configurations for ONE_TO_ONE_NAT presence

2. **VM Shielded Instance Enforcement** (`vm_shielded.rego`)
   - Ensures VMs are created with Shielded VM security features enabled
   - Implements NIST SI-7 (Software Integrity) controls
   - Verifies secure boot, vTPM, and integrity monitoring configurations

3. **Storage Public Access Prevention** (`bucket_no_public_access.rego`)
   - Prevents exposing sensitive data through public Cloud Storage buckets
   - Implements NIST AC-3 (Access Enforcement) controls
   - Examines IAM bindings for `allUsers` and `allAuthenticatedUsers` principals

Each policy is designed for high performance, minimal false positives, and clear violation reporting.

## Comprehensive Testing Framework

This project includes a sophisticated multi-layer testing approach to ensure policy correctness and system reliability:

### 1. Local Policy Testing

The included `test_policy.py` utility allows for rapid, iterative testing of policies against sample configurations without requiring GCP deployment:

```bash
# Install dependencies
pip install -r requirements.txt
pip install colorama  # For test output formatting

# Generate sample configurations (if needed)
python test_policy.py --generate-samples

# Test specific resource types
python test_policy.py --resource-type=compute.googleapis.com/Instance

# Test specific policies
python test_policy.py --policy=./policies/gcp/compute/Instance/vm_shielded.rego

# Test against specific configurations
python test_policy.py --config=./samples/vm_not_shielded.json
```

### 2. Local Function Testing

Test the Cloud Function locally before deployment:

```bash
# Install the Functions Framework
pip install functions-framework

# Download required binaries
# For Windows:
curl -L -o opa.exe https://github.com/open-policy-agent/opa/releases/download/v0.52.0/opa_windows_amd64.exe
curl -L -o cosign.exe https://github.com/sigstore/cosign/releases/download/v2.1.1/cosign-windows-amd64.exe

# Start the local function server
functions-framework --target=policy_enforcement_handler --signature-type=cloudevent
```

### 3. Integration Testing in GCP

After deployment, verify end-to-end functionality:

```bash
# Create a test VM with a public IP (should trigger violation)
gcloud compute instances create test-violation-vm \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --network-interface=subnet=default,access-config

# Check logs for violations
gcloud functions logs read policy-enforcement-handler --limit=50

# Clean up test resources
gcloud compute instances delete test-violation-vm --zone=us-central1-a --quiet
```

### 4. ChainGuard Container Verification Testing

Specifically test the ChainGuard integration:

```bash
# Use Cosign to sign a test container image
COSIGN_PASSWORD="" cosign generate-key-pair
cosign sign --key cosign.key my-container-registry.io/my-app:latest

# Deploy a container with and without signatures to test detection
```

## Prerequisites

- Google Cloud Project with billing enabled
- Required APIs enabled:
  - Cloud Functions
  - Eventarc
  - Cloud Asset Inventory
  - Pub/Sub
  - Cloud Logging
  - Resource Manager
- Service account with appropriate permissions
- OPA binary for policy evaluation
- Cosign binary for ChainGuard/Sigstore verification (if using container security)

## Setup & Deployment

Follow these steps to deploy the framework to your GCP environment:

### 1. Clone this Repository

```bash
git clone https://github.com/MikeDominic92/Serverless-Security-Policy-Enforcement-Framework-with-ChainGuard-Integration-on-GCP.git
cd Serverless-Security-Policy-Enforcement-Framework-with-ChainGuard-Integration-on-GCP
```

### 2. Configure GCP Project

```bash
# Set your GCP project ID
export PROJECT_ID="your-gcp-project-id"
gcloud config set project $PROJECT_ID

# Enable required APIs
gcloud services enable cloudfunctions.googleapis.com \
    cloudbuild.googleapis.com \
    eventarc.googleapis.com \
    pubsub.googleapis.com \
    cloudasset.googleapis.com
```

### 3. Run the Deployment Script

```bash
# Make the script executable
chmod +x deployment/setup.sh

# Run the deployment script (works on Linux/Mac or WSL on Windows)
./deployment/setup.sh --project-id=$PROJECT_ID --region=us-central1
```

The script performs the following:

1. Creates IAM service accounts with least privilege permissions
2. Configures Eventarc triggers on Cloud Audit Logs
3. Sets up Pub/Sub topics for event routing and notifications
4. Downloads OPA and Cosign binaries for policy evaluation and ChainGuard verification
5. Deploys the Cloud Function with appropriate environment variables

### 4. Verify Deployment

```bash
# Check if the Cloud Function was deployed successfully
gcloud functions describe policy-enforcement-handler --gen2 --region=us-central1

# Test with a sample event (create a compliant and non-compliant resource)
```

## Custom Policy Development

Extend the framework with your own security policies:

### 1. Create a New Rego Policy

Create a `.rego` file in the appropriate directory structure under `src/policy_handler/policies/gcp/`. Follow this template:

```rego
package policy.gcp.RESOURCE_TYPE.POLICY_NAME

import future.keywords.in

violation[result] {
    # Define conditions for policy violation
    # Example: resource has a specific configuration
    
    result := {
        "policy": "POLICY_NAME",
        "resource": input.name,
        "message": "Violation details...",
        "severity": "HIGH"  # or MEDIUM, LOW
    }
}
```

### 2. Create Test Cases

Add sample JSON files in `src/policy_handler/samples/` with examples of compliant and non-compliant configurations.

### 3. Test Your Policy

```bash
python test_policy.py --policy=./policies/gcp/RESOURCE_TYPE/RESOURCE_SUBTYPE/your_policy.rego
```

### 4. Add NIST Control Mapping

Update `docs/nist_compliance_mapping.md` to include your new policy and its corresponding NIST control.

## Production Considerations

Before deploying to a production environment, consider these additional recommendations:

### Performance Optimization

1. **Function Memory Allocation**: Increase memory allocation for the Cloud Function to improve policy evaluation performance (1-2GB recommended for large environments)

2. **Selective Triggers**: Configure Eventarc triggers to only capture relevant resource types to reduce unnecessary evaluations

3. **Batched Processing**: For large volumes, consider implementing batched processing of events

### Operational Readiness

1. **Monitoring Dashboard**: Create a Cloud Monitoring dashboard to track function invocations, errors, and policy violations

2. **Alert Policies**: Set up alert thresholds for critical violations that require immediate attention

3. **Log Exports**: Configure log exports to your SIEM system for centralized security monitoring

### Security Enhancements

1. **VPC Service Controls**: Deploy within a VPC Service Perimeter for added network isolation

2. **Secret Management**: Use Secret Manager for sensitive configuration values

3. **Regularly Audit IAM**: Review service account permissions to maintain least-privilege

### High Availability

1. **Multi-Region Deployment**: Consider deploying to multiple regions for resilience

2. **Dead-Letter Topic**: Configure a dead-letter topic for handling failed events

## Contributing

Contributions to enhance this framework are welcomed! Here's how you can contribute:

1. **Submit Issues**: Report bugs, suggest features, or ask questions via GitHub Issues

2. **Pull Requests**: Submit PRs with bug fixes, new policies, or feature enhancements

3. **Policy Contributions**: Share your custom security policies with the community

4. **Documentation**: Improve or expand the documentation and examples

Before submitting a PR, please:

- Test your changes thoroughly with the provided testing framework
- Update documentation to reflect your changes
- Add your name to the contributors list in this README

### Contributors

- [MikeDominic92](https://github.com/MikeDominic92) - Framework architect and initial implementation

## License

This project is licensed under the MIT License - see the LICENSE file for details.

```text
MIT License

Copyright (c) 2025 MikeDominic92

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
