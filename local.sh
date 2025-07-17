#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- Configuration ---
LOCAL_IMAGE_TAG="alder-security-scanner:local" # Tag for locally built images
ENV_FILE=".env"
REPORTS_DIR="./local-reports"
# -------------------

# --- Argument Parsing ---
if [ -z "$1" ]; then
  echo "Usage: ./local.sh <path_to_repo_to_scan>"
  echo "Example: ./local.sh ../my-test-repo"

  exit 1
fi

REPO_PATH="$1"

if [ ! -d "$REPO_PATH" ]; then
  echo "Error: Repository path '$REPO_PATH' not found."
  exit 1
fi

# Convert repo path to absolute path for Docker volume mounting
REPO_ABS_PATH=$(cd "$REPO_PATH" && pwd)

# --- Pre-run Checks ---
# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE file not found."
    echo "Please create an $ENV_FILE file with your GEMINI_API_KEY and OPENAI_API_KEY."
    exit 1
fi

# Check if docker is running
if ! docker info > /dev/null 2>&1; then
  echo "Error: Docker does not seem to be running, please start it and try again."
  exit 1
fi

# Source environment variables
source "$ENV_FILE"

# Check required environment variables are loaded
if [ -z "$GEMINI_API_KEY" ] || [ -z "$OPENAI_API_KEY" ]; then
  echo "Error: One or more required environment variables (GEMINI_API_KEY, OPENAI_API_KEY) are missing from $ENV_FILE."
  exit 1
fi
# ---------------------

# --- Build Docker Image Locally ---
echo "Building Docker image locally for your Mac..."
export DOCKER_BUILDKIT=1 # Enable BuildKit for efficient builds
# Building with the Dockerfile in the current directory (.)
docker build -t "$LOCAL_IMAGE_TAG" .
echo "Docker image built and tagged as: $LOCAL_IMAGE_TAG"
# ---------------------------------

# --- Setup ---
# Create reports directory
mkdir -p "$REPORTS_DIR"
REPORTS_ABS_PATH=$(cd "$REPORTS_DIR" && pwd)

echo "Scanning repository: $REPO_ABS_PATH"
echo "Reports will be saved to: $REPORTS_ABS_PATH"
# -------------

# --- Run Docker Container ---
echo "Starting Docker container..."

docker run --rm -it \
  -e GEMINI_API_KEY="$GEMINI_API_KEY" \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e INPUT_EXTRA_IGNORE_DIRS="" \
  "$LOCAL_IMAGE_TAG"

# --- Completion ---
echo "---------------------------------------------------"
echo "Local scan finished."
echo "Reports should be available in: $REPORTS_DIR"
echo "---------------------------------------------------"
# ----------------
