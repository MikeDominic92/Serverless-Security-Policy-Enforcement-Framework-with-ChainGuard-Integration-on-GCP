import base64
import json
import functions_framework
import google.cloud.logging
from google.cloud import asset_v1
from google.cloud import pubsub_v1
import os
import subprocess
import glob
import time
import re
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.json_format import MessageToDict

# --- Configuration ---
# Replace with your actual Project ID or use env vars in production
YOUR_PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
NOTIFICATION_TOPIC = "policy-violation-notifications"
POLICY_BASE_DIR = "./policies"
OPA_BINARY = "./opa" # Path to OPA binary if using subprocess approach
COSIGN_BINARY = "./cosign" # Path to cosign binary if using subprocess approach

# --- Initialize GCP Clients ---
try:
    logging_client = google.cloud.logging.Client()
    asset_client = asset_v1.AssetServiceClient()
    publisher = pubsub_v1.PublisherClient()
    log_name = "policy-enforcement-framework"
    violation_log_name = "policy-enforcement-violations"
    gcp_logger = logging_client.logger(log_name)
    violation_logger = logging_client.logger(violation_log_name)
    notification_topic_path = publisher.topic_path(YOUR_PROJECT_ID, NOTIFICATION_TOPIC)
    gcp_logger.log_text("Clients initialized successfully.", severity="INFO")
except Exception as e:
    print(f"CRITICAL: Failed to initialize GCP clients: {e}")
    # Use print for early errors as logging might not be set up
    gcp_logger = None # Indicate failure

# --- Main Handler ---
@functions_framework.cloud_event
def policy_enforcement_handler(cloud_event):
    """
    Main handler function triggered by Pub/Sub messages.
    Orchestrates the policy evaluation workflow.
    """
    if not gcp_logger:
        print("CRITICAL: Logging client not available. Aborting function.")
        return

    try:
        gcp_logger.log_struct({
            "message": "Function triggered.", 
            "event_id": cloud_event.id, 
            "event_type": cloud_event.type
        })

        # 1. Decode and Parse Event
        event_payload = decode_event_data(cloud_event)
        if not event_payload:
            return # Error already logged in helper function

        # 2. Extract Resource Information
        resource_name = extract_resource_name(event_payload)
        if not resource_name:
            gcp_logger.log_struct({
                "message": "Could not determine resource name from event.", 
                "payload_preview": str(event_payload)[:200]
            }, severity="WARNING")
            return

        gcp_logger.log_struct({
            "message": f"Processing event for resource: {resource_name}", 
            "resource_name": resource_name, 
            "event_id": cloud_event.id
        })

        # 3. Fetch Resource Configuration
        config = get_resource_configuration(resource_name)
        if config is None:
            gcp_logger.log_struct({
                "message": f"Could not fetch configuration for {resource_name}. Resource might be deleted or inaccessible.", 
                "resource_name": resource_name
            }, severity="WARNING")
            return

        # 4. Evaluate Policies against Configuration
        policy_violations = evaluate_policies(resource_name, config)

        # 5. Perform ChainGuard Supply Chain Checks (Conditional)
        supply_chain_violations = []
        if should_check_supply_chain(resource_name, config):
            supply_chain_violations = check_chainguard(resource_name, config, event_payload)

        # 6. Handle Results (Violations or Compliance)
        all_violations = policy_violations + supply_chain_violations
        handle_results(resource_name, all_violations, config)

    except Exception as e:
        # Catch-all for unexpected errors during processing
        gcp_logger.log_text(f"Unhandled exception in policy_enforcement_handler: {e}", severity="CRITICAL")
        raise  # Re-raise to trigger retry mechanisms if configured

# --- Helper Functions ---

def decode_event_data(cloud_event):
    """
    Decodes base64 data from Pub/Sub message in CloudEvent.
    Returns the decoded event payload as a Python dict.
    """
    try:
        if not cloud_event.data or "message" not in cloud_event.data or "data" not in cloud_event.data["message"]:
            gcp_logger.log_text("Received event with missing data structure.", severity="WARNING")
            return None

        encoded_data = cloud_event.data["message"]["data"]
        decoded_data = base64.b64decode(encoded_data).decode("utf-8")
        return json.loads(decoded_data)
    except (KeyError, TypeError, ValueError, base64.binascii.Error, json.JSONDecodeError) as e:
        gcp_logger.log_text(f"Error decoding event data: {e}", severity="ERROR")
        return None

def extract_resource_name(payload):
    """
    Extracts the full resource name from the event payload (e.g., Audit Log).
    Handles common payload structures from CloudAudit logs.
    """
    try:
        # Handle Cloud Audit Log structure
        if 'protoPayload' in payload and isinstance(payload['protoPayload'], dict):
            proto_payload = payload['protoPayload']
            
            # Direct resource name in protoPayload
            if 'resourceName' in proto_payload and proto_payload['resourceName']:
                return proto_payload['resourceName']
                
            # Resource name in resource object
            if 'resource' in proto_payload and isinstance(proto_payload['resource'], dict):
                if 'name' in proto_payload['resource'] and proto_payload['resource']['name']:
                    return proto_payload['resource']['name']
                    
            # Look in requestMetadata
            if 'requestMetadata' in proto_payload and isinstance(proto_payload['requestMetadata'], dict):
                if 'callerSuppliedResourceName' in proto_payload['requestMetadata'] and proto_payload['requestMetadata']['callerSuppliedResourceName']:
                    return proto_payload['requestMetadata']['callerSuppliedResourceName']
        
        # Handle Cloud Storage direct events (for Eventarc)
        if payload.get('kind') == 'storage#object' and 'name' in payload and 'bucket' in payload:
            return f"//storage.googleapis.com/projects/_/buckets/{payload['bucket']}/objects/{payload['name']}"

    except (KeyError, TypeError) as e:
        gcp_logger.log_text(f"Error extracting resource name: {e}", severity="WARNING")
    
    return None

def get_resource_configuration(resource_name):
    """
    Fetches the current configuration of a GCP resource using Cloud Asset Inventory.
    Returns the resource configuration as a dictionary, or None if not found/error.
    """
    try:
        # Extract project ID from resource_name
        match = re.search(r"projects/([^/]+)", resource_name)
        if not match:
            gcp_logger.log_text(f"Could not parse project ID from resource name: {resource_name}", severity="ERROR")
            return None
            
        project_id = match.group(1)
        scope = f"projects/{project_id}"

        # Use current time for read_time_window end
        read_time = Timestamp()
        read_time.FromNanoseconds(time.time_ns())

        request = asset_v1.BatchGetAssetsHistoryRequest(
            parent=scope,
            asset_names=[resource_name],
            content_type=asset_v1.ContentType.RESOURCE,  # Fetch the resource config itself
            read_time_window=asset_v1.TimeWindow(end_time=read_time),
        )
        
        gcp_logger.log_text(f"Requesting asset history for {resource_name}")
        response = asset_client.batch_get_assets_history(request=request)

        if response.assets:
            # Get the latest asset
            latest_asset = response.assets[0]  # Usually the first/only one for a point-in-time query
            
            if latest_asset.resource:
                gcp_logger.log_text(f"Successfully fetched configuration for {resource_name}")
                # Convert protobuf to Python dictionary
                config_dict = MessageToDict(latest_asset.resource)
                return config_dict
            else:
                gcp_logger.log_text(f"Asset history found for {resource_name}, but no resource data", severity="WARNING")
                return None
        else:
            gcp_logger.log_text(f"No asset history found for {resource_name}", severity="WARNING")
            return None

    except Exception as e:
        gcp_logger.log_text(f"Error fetching asset configuration for {resource_name}: {e}", severity="ERROR")
        return None

def get_resource_type_from_name(resource_name):
    """
    Extracts service and resource type like 'compute.googleapis.com/Instance'
    from a resource name.
    """
    try:
        parts = resource_name.split('/')
        if len(parts) >= 3 and parts[0] == '':  # Check for leading //
            service_domain = parts[2]
            
            # Map common resource patterns to their types
            type_mapping = {
                "instances": "Instance",
                "buckets": "Bucket",
                "disks": "Disk",
                "firewalls": "Firewall",
                "topics": "Topic",
                "subscriptions": "Subscription",
                "services": "Service",
                "clusters": "Cluster",
            }
            
            # Find the resource kind from the path (usually the second-to-last segment before ID)
            for i in range(len(parts) - 1):
                if parts[i] in type_mapping:
                    return f"{service_domain}/{type_mapping[parts[i]]}"
            
            # Fallback: return unknown type with the service
            return f"{service_domain}/Unknown"
            
    except Exception as e:
        gcp_logger.log_text(f"Error parsing resource type from name {resource_name}: {e}", severity="WARNING")
        
    return "unknown/Unknown"

def find_policy_files(resource_type):
    """
    Finds .rego policy files for a given resource type.
    Returns a list of file paths.
    """
    if not resource_type or '/' not in resource_type:
        return []
    
    service, kind = resource_type.split('/', 1)  # Split only once
    # Normalize service name (e.g., compute.googleapis.com -> compute)
    service_short = service.split('.')[0]
    
    # Construct path: ./policies/gcp/compute/Instance/*.rego
    policy_dir = os.path.join(POLICY_BASE_DIR, "gcp", service_short, kind)
    
    if os.path.isdir(policy_dir):
        pattern = os.path.join(policy_dir, "*.rego")
        found_files = glob.glob(pattern)
        gcp_logger.log_struct({
            "message": f"Found {len(found_files)} policies for {resource_type}",
            "directory": policy_dir,
            "files": found_files
        }, severity="DEBUG")
        return found_files
    else:
        gcp_logger.log_text(f"Policy directory not found for {resource_type}: {policy_dir}", severity="DEBUG")
        return []

def evaluate_policies(resource_name, config):
    """
    Evaluates the resource config against relevant Rego policies using OPA.
    Returns a list of violation dictionaries.
    """
    violations = []
    resource_type = get_resource_type_from_name(resource_name)
    policy_files = find_policy_files(resource_type)

    if not policy_files:
        gcp_logger.log_struct({
            "message": f"No Rego policies found for resource type {resource_type}",
            "resource_name": resource_name
        }, severity="INFO")
        return violations

    gcp_logger.log_struct({
        "message": f"Evaluating {len(policy_files)} policies for {resource_name}",
        "resource_type": resource_type
    })

    # Check if OPA binary exists (if using subprocess approach)
    if not os.path.exists(OPA_BINARY):
        gcp_logger.log_text(f"OPA binary '{OPA_BINARY}' not found. Cannot evaluate policies.", severity="CRITICAL")
        violations.append({
            "policy_id": "framework_error", 
            "message": "OPA binary missing, cannot evaluate policies",
            "metadata": {"resource_type": resource_type}
        })
        return violations

    try:
        # Convert config to JSON for OPA input
        input_json = json.dumps(config)
        
        # Build OPA command to evaluate policies
        # Query "data" to get all results
        cmd = [OPA_BINARY, "eval", "--input", "-", "--format", "json", "data"]
        
        # Add each policy file to the command
        for f in policy_files:
            cmd.extend(["--data", f])

        # Run OPA command
        process = subprocess.run(
            cmd, 
            input=input_json, 
            text=True,
            capture_output=True, 
            check=False,  # Don't raise exception on non-zero exit
            timeout=30
        )

        if process.returncode != 0:
            gcp_logger.log_text(
                f"OPA evaluation failed: {process.stderr}", 
                severity="ERROR"
            )
            violations.append({
                "policy_id": "framework_error",
                "message": f"OPA execution failed: {process.stderr[:200]}",
                "metadata": {"resource_type": resource_type}
            })
            return violations

        # Parse OPA results
        raw_results = json.loads(process.stdout)
        
        # Extract violations from results
        # This assumes policies use the 'violation' rule pattern
        if raw_results and 'result' in raw_results:
            all_violations = extract_violations_recursive(raw_results['result'])
            violations.extend(all_violations)

        # Log results
        if violations:
            gcp_logger.log_struct({
                "message": f"Found {len(violations)} policy violations for {resource_name}",
                "resource_name": resource_name,
                "violation_count": len(violations)
            }, severity="WARNING")
        else:
            gcp_logger.log_struct({
                "message": f"No policy violations found for {resource_name}",
                "resource_name": resource_name
            }, severity="INFO")

    except FileNotFoundError:
        gcp_logger.log_text(f"OPA binary '{OPA_BINARY}' not found despite initial check.", severity="CRITICAL")
        violations.append({
            "policy_id": "framework_error", 
            "message": "OPA binary not found during execution",
            "metadata": {}
        })
    except subprocess.TimeoutExpired:
        gcp_logger.log_text(f"OPA evaluation timed out for {resource_name}", severity="ERROR")
        violations.append({
            "policy_id": "framework_error", 
            "message": "OPA evaluation timed out after 30 seconds",
            "metadata": {}
        })
    except json.JSONDecodeError as e:
        gcp_logger.log_text(f"Failed to parse OPA output: {e}", severity="ERROR")
        violations.append({
            "policy_id": "framework_error", 
            "message": f"Failed to parse OPA JSON output: {e}",
            "metadata": {}
        })
    except Exception as e:
        gcp_logger.log_text(f"Unexpected error during policy evaluation: {e}", severity="ERROR")
        violations.append({
            "policy_id": "framework_error", 
            "message": f"Unexpected error: {str(e)}",
            "metadata": {}
        })

    return violations

def extract_violations_recursive(data):
    """
    Recursively searches for 'violation' keys in the OPA result data structure.
    """
    found = []
    if isinstance(data, dict):
        # If 'violation' key exists and is a non-empty list, collect its items
        if "violation" in data and isinstance(data["violation"], list) and data["violation"]:
            found.extend(data["violation"])
            
        # Recurse into dictionary values
        for key, value in data.items():
            if key != "violation":  # Avoid duplicate processing
                found.extend(extract_violations_recursive(value))
                
    elif isinstance(data, list):
        # Recurse into list items
        for item in data:
            found.extend(extract_violations_recursive(item))
            
    return found

def should_check_supply_chain(resource_name, config):
    """
    Determines if supply chain checks are applicable to this resource type.
    """
    resource_type = get_resource_type_from_name(resource_name)
    
    # Resource types that typically involve container images
    container_resource_types = [
        "run.googleapis.com/Service",
        "container.googleapis.com/Cluster",
        "cloudfunctions.googleapis.com/Function"  # If 2nd gen functions use containers
    ]
    
    if resource_type in container_resource_types:
        # Check if resource config contains container image references
        image_ref = extract_image_reference(config)
        if image_ref:
            gcp_logger.log_struct({
                "message": f"Supply chain check applicable for {resource_type}: {resource_name}",
                "image_reference": image_ref
            }, severity="DEBUG")
            return True
            
    return False

def extract_image_reference(config):
    """
    Extracts container image reference(s) from resource config.
    Handles different resource types that might contain image references.
    """
    # Extract from Cloud Run Service
    try:
        if config.get('spec', {}).get('template', {}).get('spec', {}).get('containers'):
            containers = config['spec']['template']['spec']['containers']
            if containers and isinstance(containers, list) and len(containers) > 0:
                return containers[0].get('image')
    except (KeyError, IndexError, TypeError):
        pass
        
    # Could add more extraction logic for other resource types
    
    return None

def check_chainguard(resource_name, config, event_payload):
    """
    Performs ChainGuard/Sigstore verification on container images.
    """
    violations = []
    gcp_logger.log_text(f"Performing ChainGuard checks for {resource_name}", severity="INFO")
    
    # Extract image reference
    image_ref = extract_image_reference(config)
    if not image_ref:
        gcp_logger.log_text(f"Could not extract image reference for supply chain check", severity="WARNING")
        return violations

    # Check if cosign binary is available
    if not os.path.exists(COSIGN_BINARY):
        gcp_logger.log_text(f"Cosign binary '{COSIGN_BINARY}' not found.", severity="CRITICAL")
        violations.append({
            "policy_id": "supply_chain_error", 
            "message": "Cosign binary missing, cannot verify image signatures",
            "metadata": {"image": image_ref}
        })
        return violations

    try:
        # Configure expected identity/issuer based on policy
        expected_issuer = os.environ.get("EXPECTED_SIGSTORE_ISSUER", "https://accounts.google.com")
        expected_identity = os.environ.get(
            "EXPECTED_SIGSTORE_IDENTITY_REGEX", 
            ".*@your-builder-project\\.iam\\.gserviceaccount\\.com"
        )
        
        # Build cosign verify command
        cmd = [
            COSIGN_BINARY, "verify",
            "--output", "text",
            "--certificate-oidc-issuer", expected_issuer,
            "--certificate-identity-regexp", expected_identity,
            image_ref
        ]

        # Run cosign verify command
        gcp_logger.log_text(f"Running cosign verify for {image_ref}")
        process = subprocess.run(
            cmd, 
            text=True, 
            capture_output=True, 
            check=False,
            timeout=60
        )

        # Check verification results
        if process.returncode == 0:
            gcp_logger.log_text(f"Cosign verification successful for {image_ref}", severity="INFO")
        else:
            gcp_logger.log_text(
                f"Cosign verification FAILED for {image_ref}. Return Code: {process.returncode}", 
                severity="WARNING"
            )
            violations.append({
                "policy_id": "supply_chain_violation",
                "message": "Image signature verification failed",
                "metadata": {
                    "image": image_ref,
                    "error": process.stderr[:500] if process.stderr else "Unknown error"
                }
            })

    except FileNotFoundError:
        gcp_logger.log_text(f"Cosign binary '{COSIGN_BINARY}' missing during execution.", severity="CRITICAL")
        violations.append({
            "policy_id": "supply_chain_error", 
            "message": "Cosign binary not found during execution",
            "metadata": {"image": image_ref}
        })
    except subprocess.TimeoutExpired:
        gcp_logger.log_text(f"Cosign verification timed out for {image_ref}", severity="ERROR")
        violations.append({
            "policy_id": "supply_chain_error", 
            "message": "Cosign verification timed out after 60 seconds",
            "metadata": {"image": image_ref}
        })
    except Exception as e:
        gcp_logger.log_text(f"Unexpected error during cosign verification: {e}", severity="ERROR")
        violations.append({
            "policy_id": "supply_chain_error", 
            "message": f"Unexpected error: {str(e)}",
            "metadata": {"image": image_ref}
        })

    return violations

def handle_results(resource_name, all_violations, config):
    """
    Handles policy evaluation results - logs violations, sends notifications,
    and optionally applies remediation actions.
    """
    is_compliant = len(all_violations) == 0

    if is_compliant:
        gcp_logger.log_struct({
            "message": f"Resource {resource_name} is compliant with all policies",
            "resource_name": resource_name
        }, severity="INFO")
        # Could add optional tagging for compliant resources
    else:
        # Log violations
        gcp_logger.log_struct({
            "message": f"Resource {resource_name} has {len(all_violations)} violation(s)",
            "resource_name": resource_name,
            "violation_count": len(all_violations)
        }, severity="WARNING")
        
        # Log detailed violations to a specific log
        violation_logger.log_struct({
            "resource_name": resource_name,
            "violations": all_violations,
            "timestamp": time.time(),
            # Including a safe subset of config to avoid sensitive data
            "resource_type": get_resource_type_from_name(resource_name)
        }, severity="WARNING")

        # Send notification
        send_notification(resource_name, all_violations)
        
        # Could add remediation here in the future
        # maybe_remediate(resource_name, all_violations, config)

def send_notification(resource_name, violations):
    """
    Publishes violation details to a Pub/Sub topic for notification handling.
    """
    try:
        # Prepare message data
        message_data = json.dumps({
            "resource_name": resource_name,
            "timestamp": time.time(),
            "violations": violations,
            "resource_type": get_resource_type_from_name(resource_name)
        }).encode("utf-8")
        
        # Publish message
        future = publisher.publish(notification_topic_path, message_data)
        message_id = future.result()  # Wait for publish to complete
        
        gcp_logger.log_struct({
            "message": f"Successfully published violation notification",
            "message_id": message_id,
            "resource_name": resource_name,
            "violation_count": len(violations)
        }, severity="INFO")
        
    except Exception as e:
        gcp_logger.log_text(
            f"Error publishing notification for {resource_name}: {e}", 
            severity="ERROR"
        )

# --- Placeholder functions for future implementation ---

def tag_resource(resource_name, is_compliant, violations=None):
    """
    Placeholder for tagging resources with compliance status.
    """
    # This would use Resource Manager API to apply tags
    gcp_logger.log_text(f"Resource tagging not implemented yet: {resource_name}", severity="DEBUG")

def maybe_remediate(resource_name, violations, config):
    """
    Placeholder for automatic remediation actions.
    """
    # This would implement service-specific remediation actions
    gcp_logger.log_text(f"Automatic remediation not implemented yet: {resource_name}", severity="DEBUG")

# For local development/testing
if __name__ == "__main__":
    print("Local development mode - this script would run as a Cloud Function.")
    print("To test locally, you would need to:")
    print("1. Use functions-framework package to serve the function")
    print("2. Provide mock CloudEvent data for testing")
    print("Example: functions-framework --target=policy_enforcement_handler --signature-type=cloudevent")
