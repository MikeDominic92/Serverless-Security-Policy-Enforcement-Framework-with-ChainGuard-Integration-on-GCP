# Serverless Security Policy Enforcement Framework with ChainGuard Integration

A comprehensive serverless framework for GCP that automatically enforces security policies across cloud resources, including supply chain verification for container images.

## Architecture Overview

This framework leverages an event-driven architecture on Google Cloud Platform:

1. **Cloud Functions**: Hosts the core policy evaluation and enforcement logic
2. **Eventarc & Audit Logs**: Captures resource change events to trigger policy evaluation
3. **Cloud Asset Inventory**: Retrieves resource configurations for evaluation
4. **Rego Policies**: Defines security rules in OPA's Rego language
5. **ChainGuard/Sigstore**: Verifies container image signatures and attestations
6. **Pub/Sub**: Handles notification delivery for violations

## Directory Structure

```
security_enforcement_framework/
└── src/
    └── policy_handler/
        ├── main.py                     # Main Cloud Function code
        ├── requirements.txt            # Python dependencies
        └── policies/                   # Rego policy directory 
            └── gcp/                    # GCP-specific policies
                ├── compute/            # Compute Engine policies
                │   └── Instance/       # VM instance policies
                │       └── vm_no_external_ip.rego
                └── storage/            # Storage policies
                    └── Bucket/         # Bucket policies
                        └── bucket_no_public_access.rego
```

## Policy Examples

The framework includes example policies:

1. **VM External IP**: Detects Compute Engine VMs with public IP addresses
2. **Storage Public Access**: Detects Cloud Storage buckets with public access
3. **[Add more policies as needed]**

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

## Setup

1. **Create a GCP project** (or use an existing one)
2. **Enable required APIs**
3. **Create service account** with necessary permissions
4. **Deploy the Cloud Function** using the deployment script
5. **Configure Eventarc** triggers for resource change events
6. **Set up notification handling** for policy violations

See the `deployment/setup.sh` script for detailed steps.

## Deployment

Run the deployment script with your GCP project ID:

```bash
cd security_enforcement_framework
./deployment/setup.sh --project-id=YOUR_PROJECT_ID
```

## Function Configuration

The function can be configured via environment variables:

- `GCP_PROJECT`: Your Google Cloud Project ID
- `EXPECTED_SIGSTORE_ISSUER`: The expected OIDC issuer for container signatures
- `EXPECTED_SIGSTORE_IDENTITY_REGEX`: Regex pattern for valid signing identities

## Adding Custom Policies

To add a new policy:

1. Create a `.rego` file in the appropriate directory (e.g., `policies/gcp/compute/Instance/`)
2. Define the policy using Rego language with a `violation` rule
3. Redeploy the function to include the new policy

## Local Testing

For local testing of the function:

```bash
cd security_enforcement_framework/src/policy_handler
pip install -r requirements.txt
functions-framework --target=policy_enforcement_handler --signature-type=cloudevent
```

Then send a test CloudEvent to the local server.

## Production Considerations

- Use a dedicated service account with least privilege
- Implement dead-letter topics for failed notifications
- Consider adding metrics and alerting
- Implement comprehensive error handling and retries
- Deploy multiple instances across regions for resilience
- Set up proper SDLC for policy updates

## License

[Your license information]

## Contributing

[Your contribution guidelines]
