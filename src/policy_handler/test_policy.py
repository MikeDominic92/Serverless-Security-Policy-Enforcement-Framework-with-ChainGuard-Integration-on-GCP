#!/usr/bin/env python3
"""
Policy Testing Utility

This script tests Rego policies locally against sample resource configurations.
It requires the OPA binary in the same directory or in your PATH.
"""

import argparse
import json
import os
import subprocess
import glob
import sys
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init()

# Configuration
OPA_BINARY = "./opa"  # Path to OPA binary
POLICY_BASE_DIR = "./policies"  # Path to policies directory
SAMPLE_DIR = "./samples"  # Path to sample configurations

def find_policy_files(resource_type):
    """Find .rego policy files for a given resource type."""
    if not resource_type or '/' not in resource_type:
        return []
    
    service, kind = resource_type.split('/', 1)  # Split only once
    # Normalize service name (e.g., compute.googleapis.com -> compute)
    service_short = service.split('.')[0]
    
    # Construct path: ./policies/gcp/compute/Instance/*.rego
    policy_dir = os.path.join(POLICY_BASE_DIR, "gcp", service_short, kind)
    
    if os.path.isdir(policy_dir):
        pattern = os.path.join(policy_dir, "*.rego")
        return glob.glob(pattern)
    else:
        print(f"{Fore.YELLOW}Policy directory not found: {policy_dir}{Style.RESET_ALL}")
        return []

def evaluate_policy(policy_file, config_file):
    """Evaluate a single policy against a configuration file."""
    print(f"\n{Fore.CYAN}Testing policy: {os.path.basename(policy_file)}{Style.RESET_ALL}")
    print(f"Against config: {os.path.basename(config_file)}")
    
    # Check if OPA binary exists
    if not os.path.exists(OPA_BINARY) and not which(OPA_BINARY):
        print(f"{Fore.RED}Error: OPA binary not found at {OPA_BINARY} or in PATH{Style.RESET_ALL}")
        print("Download it from: https://github.com/open-policy-agent/opa/releases")
        return None

    # Read the config file
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"{Fore.RED}Error reading config file: {e}{Style.RESET_ALL}")
        return None

    # Run OPA evaluation
    try:
        cmd = [OPA_BINARY, "eval", "--input", config_file, "--data", policy_file, 
               "--format", "json", "data"]
        
        process = subprocess.run(cmd, text=True, capture_output=True, check=False)
        
        if process.returncode != 0:
            print(f"{Fore.RED}OPA evaluation failed: {process.stderr}{Style.RESET_ALL}")
            return None
        
        # Parse the results
        results = json.loads(process.stdout)
        return extract_violations(results, os.path.basename(policy_file))
        
    except Exception as e:
        print(f"{Fore.RED}Error during policy evaluation: {e}{Style.RESET_ALL}")
        return None

def extract_violations(results, policy_name):
    """Extract violations from OPA evaluation results."""
    violations = []
    
    if not results or 'result' not in results:
        return violations
    
    def find_violations_recursive(data, path=""):
        found = []
        if isinstance(data, dict):
            # If 'violation' key exists and is a non-empty list, collect its items
            if "violation" in data and isinstance(data["violation"], list) and data["violation"]:
                for v in data["violation"]:
                    if isinstance(v, dict):
                        # Add policy info if not present
                        if "policy_id" not in v:
                            v["policy_id"] = policy_name.replace(".rego", "")
                        found.append(v)
            
            # Recurse into dict values
            for key, value in data.items():
                if key != "violation":  # Avoid duplicates
                    new_path = f"{path}.{key}" if path else key
                    found.extend(find_violations_recursive(value, new_path))
        
        elif isinstance(data, list):
            # Recurse into list items
            for i, item in enumerate(data):
                new_path = f"{path}[{i}]"
                found.extend(find_violations_recursive(item, new_path))
                
        return found
    
    return find_violations_recursive(results['result'])

def which(program):
    """Find executable in PATH (cross-platform equivalent of 'which')."""
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

def test_all_policies(resource_type, config_files):
    """Test all policies for a resource type against all provided configs."""
    policy_files = find_policy_files(resource_type)
    
    if not policy_files:
        print(f"{Fore.RED}No policies found for resource type: {resource_type}{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}Found {len(policy_files)} policies for {resource_type}{Style.RESET_ALL}")

    results = {}
    
    for config_file in config_files:
        config_name = os.path.basename(config_file)
        results[config_name] = {'compliant': [], 'violations': []}
        
        for policy_file in policy_files:
            policy_name = os.path.basename(policy_file)
            violations = evaluate_policy(policy_file, config_file)
            
            if violations:
                results[config_name]['violations'].append({
                    'policy': policy_name,
                    'details': violations
                })
            else:
                results[config_name]['compliant'].append(policy_name)
    
    # Print summary
    print(f"\n{Fore.CYAN}=== EVALUATION SUMMARY ==={Style.RESET_ALL}")
    for config_name, result in results.items():
        print(f"\n{Fore.YELLOW}Config: {config_name}{Style.RESET_ALL}")
        
        if result['compliant']:
            print(f"{Fore.GREEN}Compliant with {len(result['compliant'])} policies:{Style.RESET_ALL}")
            for policy in result['compliant']:
                print(f"  ✓ {policy}")
        
        if result['violations']:
            print(f"{Fore.RED}Violations in {len(result['violations'])} policies:{Style.RESET_ALL}")
            for v in result['violations']:
                print(f"  ✗ {v['policy']}")
                for detail in v['details']:
                    print(f"     - {detail.get('message', 'No message')}")
                    if 'metadata' in detail and detail['metadata']:
                        severity = detail['metadata'].get('severity', 'MEDIUM')
                        compliance = ', '.join(detail['metadata'].get('compliance', []))
                        print(f"       Severity: {severity}")
                        if compliance:
                            print(f"       Compliance: {compliance}")

def create_sample_dir():
    """Create sample directory if it doesn't exist."""
    os.makedirs(SAMPLE_DIR, exist_ok=True)

def generate_sample_configs():
    """Generate sample configurations for testing."""
    # Sample VM with external IP (violates vm_no_external_ip.rego)
    vm_external_ip = {
        "name": "vm-with-external-ip",
        "networkInterfaces": [
            {
                "network": "global/networks/default",
                "accessConfigs": [
                    {
                        "type": "ONE_TO_ONE_NAT",
                        "name": "External NAT"
                    }
                ]
            }
        ]
    }
    
    # Sample VM without external IP (compliant with vm_no_external_ip.rego)
    vm_no_external_ip = {
        "name": "vm-without-external-ip",
        "networkInterfaces": [
            {
                "network": "global/networks/default",
                "accessConfigs": []
            }
        ]
    }
    
    # Sample VM with shielded instance (compliant with vm_shielded.rego)
    vm_shielded = {
        "name": "vm-shielded",
        "networkInterfaces": [
            {
                "network": "global/networks/default",
                "accessConfigs": []
            }
        ],
        "shieldedInstanceConfig": {
            "enableSecureBoot": True,
            "enableVtpm": True,
            "enableIntegrityMonitoring": True
        }
    }
    
    # Sample VM without shielded instance (violates vm_shielded.rego)
    vm_not_shielded = {
        "name": "vm-not-shielded",
        "networkInterfaces": [
            {
                "network": "global/networks/default",
                "accessConfigs": []
            }
        ],
        "shieldedInstanceConfig": {
            "enableSecureBoot": False,
            "enableVtpm": True,
            "enableIntegrityMonitoring": True
        }
    }
    
    # Sample Storage bucket with public access (violates bucket_no_public_access.rego)
    bucket_public = {
        "name": "public-bucket",
        "iamConfiguration": {
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["allUsers"]
                }
            ]
        }
    }
    
    # Sample Storage bucket without public access (compliant with bucket_no_public_access.rego)
    bucket_private = {
        "name": "private-bucket",
        "iamConfiguration": {
            "bindings": [
                {
                    "role": "roles/storage.objectViewer",
                    "members": ["user:john@example.com"]
                }
            ]
        }
    }
    
    # Write sample configs to files
    samples = {
        "vm_external_ip.json": vm_external_ip,
        "vm_no_external_ip.json": vm_no_external_ip,
        "vm_shielded.json": vm_shielded,
        "vm_not_shielded.json": vm_not_shielded,
        "bucket_public.json": bucket_public,
        "bucket_private.json": bucket_private
    }
    
    for filename, config in samples.items():
        with open(os.path.join(SAMPLE_DIR, filename), 'w') as f:
            json.dump(config, f, indent=2)
    
    print(f"{Fore.GREEN}Generated {len(samples)} sample configurations in {SAMPLE_DIR}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Test Rego policies against sample configurations')
    parser.add_argument('--resource-type', type=str, help='Resource type to test (e.g., compute.googleapis.com/Instance)',
                       default="compute.googleapis.com/Instance")
    parser.add_argument('--config', type=str, help='Path to specific config file to test')
    parser.add_argument('--policy', type=str, help='Path to specific policy file to test')
    parser.add_argument('--generate-samples', action='store_true', help='Generate sample configurations')
    
    args = parser.parse_args()
    
    # Create sample directory if needed
    create_sample_dir()
    
    # Generate sample configurations if requested
    if args.generate_samples:
        generate_sample_configs()
        print("Sample generation complete. Run the script again to test policies.")
        return
    
    # If specific policy and config are provided, test just those
    if args.policy and args.config:
        if os.path.exists(args.policy) and os.path.exists(args.config):
            violations = evaluate_policy(args.policy, args.config)
            if violations:
                print(f"\n{Fore.RED}Policy violations found:{Style.RESET_ALL}")
                for v in violations:
                    print(f"  ✗ {v.get('message', 'No message')}")
                    if 'metadata' in v and v['metadata']:
                        print(f"    Severity: {v['metadata'].get('severity', 'MEDIUM')}")
                        if 'compliance' in v['metadata']:
                            print(f"    Compliance: {', '.join(v['metadata']['compliance'])}")
            else:
                print(f"\n{Fore.GREEN}No policy violations found.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Policy file or config file not found.{Style.RESET_ALL}")
        return
    
    # Otherwise, test all policies for the specified resource type
    resource_type = args.resource_type
    
    # Find config files
    if args.config:
        config_files = [args.config]
    else:
        config_pattern = os.path.join(SAMPLE_DIR, "*.json")
        config_files = glob.glob(config_pattern)
    
    if not config_files:
        print(f"{Fore.YELLOW}No sample configurations found in {SAMPLE_DIR}{Style.RESET_ALL}")
        print("Run with --generate-samples to create sample configurations.")
        return
    
    # Test all applicable policies
    test_all_policies(resource_type, config_files)

if __name__ == "__main__":
    main()
