#!/bin/bash
set -e

# Serverless Security Policy Enforcement Framework - Deployment Script
# ===================================================================

# Default values
PROJECT_ID=""
REGION="us-central1"
FUNCTION_NAME="policy-enforcement-handler"
SERVICE_ACCOUNT_NAME="policy-enforcer-sa"
NOTIFICATION_TOPIC="policy-violation-notifications"
EVENTS_TOPIC="policy-evaluation-events"
OPA_VERSION="0.52.0"
COSIGN_VERSION="2.1.1"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    --project-id)
      PROJECT_ID="$2"
      shift
      shift
      ;;
    --region)
      REGION="$2"
      shift
      shift
      ;;
    --function-name)
      FUNCTION_NAME="$2"
      shift
      shift
      ;;
    --help)
      echo "Usage: ./setup.sh --project-id=YOUR_PROJECT_ID [--region=REGION] [--function-name=NAME]"
      echo ""
      echo "Required:"
      echo "  --project-id       Your Google Cloud Project ID"
      echo ""
      echo "Optional:"
      echo "  --region           GCP region (default: us-central1)"
      echo "  --function-name    Name for the Cloud Function (default: policy-enforcement-handler)"
      echo "  --help             Display this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Validate required parameters
if [ -z "$PROJECT_ID" ]; then
  echo "Error: --project-id is required"
  echo "Use --help for usage information"
  exit 1
fi

# Display settings
echo "=================================================="
echo "Serverless Security Policy Enforcement Framework"
echo "=================================================="
echo "Deployment settings:"
echo "Project ID:     $PROJECT_ID"
echo "Region:         $REGION"
echo "Function Name:  $FUNCTION_NAME"
echo "SA Name:        $SERVICE_ACCOUNT_NAME"
echo "=================================================="
echo ""

# Confirm settings
read -p "Continue with these settings? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Deployment canceled."
  exit 0
fi

# -------------- 1. Set Google Cloud Project --------------
echo "Setting Google Cloud project to $PROJECT_ID..."
gcloud config set project "$PROJECT_ID"

# -------------- 2. Enable required APIs --------------
echo "Enabling required GCP APIs..."
gcloud services enable \
  cloudfunctions.googleapis.com \
  eventarc.googleapis.com \
  cloudasset.googleapis.com \
  pubsub.googleapis.com \
  logging.googleapis.com \
  cloudresourcemanager.googleapis.com \
  iam.googleapis.com \
  secretmanager.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  run.googleapis.com

# -------------- 3. Create service account --------------
echo "Creating service account for the policy enforcement function..."
# Check if SA exists
if gcloud iam service-accounts describe "$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com" > /dev/null 2>&1; then
  echo "Service account already exists."
else
  gcloud iam service-accounts create "$SERVICE_ACCOUNT_NAME" \
    --display-name="Service Account for Policy Enforcement Function"
fi

# -------------- 4. Grant necessary IAM roles --------------
echo "Granting necessary IAM roles to service account..."
# Cloud Asset Inventory viewer to read resource configurations
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudasset.viewer"

# Logging writer for operational logs
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/logging.logWriter"

# Pub/Sub publisher for violation notifications
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:$SERVICE_ACCOUNT_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher"

# -------------- 5. Create Pub/Sub topics --------------
echo "Creating Pub/Sub topics for events and notifications..."
# Create the events topic (target for Eventarc trigger)
if gcloud pubsub topics describe "$EVENTS_TOPIC" > /dev/null 2>&1; then
  echo "Events topic already exists."
else
  gcloud pubsub topics create "$EVENTS_TOPIC"
fi

# Create the notifications topic
if gcloud pubsub topics describe "$NOTIFICATION_TOPIC" > /dev/null 2>&1; then
  echo "Notifications topic already exists."
else
  gcloud pubsub topics create "$NOTIFICATION_TOPIC"
fi

# -------------- 6. Create Cloud Function deployment package --------------
echo "Preparing function deployment package..."
TEMP_DIR=$(mktemp -d)
FUNCTION_DIR="$TEMP_DIR/function"
mkdir -p "$FUNCTION_DIR"

# Copy function code and requirements
cp -r ./src/policy_handler/* "$FUNCTION_DIR/"

# Download OPA binary for policy evaluation
echo "Downloading OPA binary ($OPA_VERSION)..."
if [ "$(uname)" == "Darwin" ]; then
  # macOS
  curl -L -o "$FUNCTION_DIR/opa" "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_darwin_amd64"
else
  # Linux
  curl -L -o "$FUNCTION_DIR/opa" "https://github.com/open-policy-agent/opa/releases/download/v${OPA_VERSION}/opa_linux_amd64_static"
fi
chmod +x "$FUNCTION_DIR/opa"

# Download Cosign binary for ChainGuard verification
echo "Downloading Cosign binary ($COSIGN_VERSION)..."
if [ "$(uname)" == "Darwin" ]; then
  # macOS
  curl -L -o "$FUNCTION_DIR/cosign" "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-darwin-amd64"
else
  # Linux
  curl -L -o "$FUNCTION_DIR/cosign" "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64"
fi
chmod +x "$FUNCTION_DIR/cosign"

# Update function configuration with the correct project ID
sed -i.bak "s/YOUR_PROJECT_ID = os.environ.get(\"GCP_PROJECT\", \"your-project-id\")/YOUR_PROJECT_ID = os.environ.get(\"GCP_PROJECT\", \"$PROJECT_ID\")/" "$FUNCTION_DIR/main.py"

# -------------- 7. Deploy the Cloud Function --------------
echo "Deploying the Cloud Function..."
# Create a Cloud Storage bucket for the function source
FUNCTION_BUCKET="${PROJECT_ID}-function-source"
if ! gsutil ls -b "gs://${FUNCTION_BUCKET}" > /dev/null 2>&1; then
  gsutil mb -l "$REGION" "gs://${FUNCTION_BUCKET}"
fi

# Zip and upload the function code
cd "$FUNCTION_DIR"
zip -r function.zip ./*
gsutil cp function.zip "gs://${FUNCTION_BUCKET}/${FUNCTION_NAME}.zip"

# Deploy the Cloud Function (2nd gen)
gcloud functions deploy "$FUNCTION_NAME" \
  --gen2 \
  --runtime=python310 \
  --region="$REGION" \
  --source="gs://${FUNCTION_BUCKET}/${FUNCTION_NAME}.zip" \
  --entry-point=policy_enforcement_handler \
  --service-account="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com" \
  --trigger-topic="$EVENTS_TOPIC" \
  --set-env-vars="GCP_PROJECT=${PROJECT_ID}" \
  --memory=512MB \
  --timeout=300s

# Clean up the temp directory
cd - > /dev/null
rm -rf "$TEMP_DIR"

# -------------- 8. Set up Eventarc trigger for Audit Logs --------------
echo "Setting up Eventarc trigger for Audit Logs to Pub/Sub..."

# Create Eventarc trigger for Compute Engine VM instance creation/updates
gcloud eventarc triggers create compute-vm-trigger \
  --location="$REGION" \
  --destination-topic="$EVENTS_TOPIC" \
  --event-filters="type=google.cloud.audit.log.v1.written" \
  --event-filters="serviceName=compute.googleapis.com" \
  --event-filters="methodName=beta.compute.instances.insert" \
  --event-filters="methodName=beta.compute.instances.update" \
  --service-account="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# Create Eventarc trigger for Cloud Storage bucket IAM changes
gcloud eventarc triggers create storage-iam-trigger \
  --location="$REGION" \
  --destination-topic="$EVENTS_TOPIC" \
  --event-filters="type=google.cloud.audit.log.v1.written" \
  --event-filters="serviceName=storage.googleapis.com" \
  --event-filters="methodName=storage.setIamPermissions" \
  --service-account="${SERVICE_ACCOUNT_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

# -------------- 9. Set up a sample notification subscriber --------------
echo "Setting up a sample notification subscriber (logs notifications to Cloud Logging)..."
gcloud pubsub subscriptions create policy-violation-logger \
  --topic="$NOTIFICATION_TOPIC" \
  --ack-deadline=60 \
  --message-retention-duration=7d

echo ""
echo "=================================================="
echo "Deployment Complete!"
echo "=================================================="
echo ""
echo "The Serverless Security Policy Enforcement Framework has been successfully deployed."
echo ""
echo "Next steps:"
echo "1. Test the framework by creating a VM with an external IP"
echo "2. Check Cloud Logging for policy evaluation results:"
echo "   https://console.cloud.google.com/logs/query?project=$PROJECT_ID"
echo "3. Add more policies to the ./src/policy_handler/policies directory"
echo "4. For production use, consider setting up more robust notification handling"
echo ""
echo "To view function logs:"
echo "gcloud functions logs read $FUNCTION_NAME --gen2 --project $PROJECT_ID --region $REGION"
echo ""
