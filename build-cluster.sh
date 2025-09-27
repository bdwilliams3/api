#!/bin/bash

# KIND Cluster Rebuild Script
# This script rebuilds your KIND cluster with API deployment and MetalLB

set -e  # Exit on any error

CLUSTER_NAME="api-cluster"
IMAGE_NAME="api:latest"
CONFIG_FILE="kind-config.yaml"
DEPLOYMENT_FILE="deployment.yaml"

echo "🚀 Starting KIND cluster rebuild..."

# Function to print colored output
print_status() {
    echo -e "\033[1;32m[INFO]\033[0m $1"
}

print_error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
}

print_warning() {
    echo -e "\033[1;33m[WARNING]\033[0m $1"
}

# Check if required files exist
if [ ! -f "$CONFIG_FILE" ]; then
    print_error "kind-config.yaml not found!"
    exit 1
fi

if [ ! -f "$DEPLOYMENT_FILE" ]; then
    print_error "api-deployment.yaml not found!"
    exit 1
fi

# Clean up existing cluster if it exists
if kind get clusters | grep -q "$CLUSTER_NAME"; then
    print_warning "Deleting existing cluster: $CLUSTER_NAME"
    kind delete cluster --name=$CLUSTER_NAME
fi

# Step 1: Create KIND cluster
print_status "Creating KIND cluster..."
kind create cluster --config=$CONFIG_FILE --name=$CLUSTER_NAME

# Step 2: Check if Docker image exists
if ! docker images | grep -q "my-api.*latest"; then
    print_warning "Docker image '$IMAGE_NAME' not found. Building..."
    if [ -f "Dockerfile" ]; then
        docker build -t $IMAGE_NAME .
    else
        print_error "Dockerfile not found! Please build your image first."
        exit 1
    fi
fi

# Step 3: Load Docker image into KIND
print_status "Loading Docker image into KIND cluster..."
kind load docker-image $IMAGE_NAME --name=$CLUSTER_NAME

# Step 4: Install MetalLB
print_status "Installing MetalLB..."
kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.12/config/manifests/metallb-native.yaml

print_status "Waiting for MetalLB to be ready..."
kubectl wait --namespace metallb-system \
  --for=condition=ready pod \
  --selector=app=metallb \
  --timeout=90s

# Step 5: Detect Docker network and configure MetalLB
print_status "Detecting KIND network subnet..."
SUBNET=$(docker network inspect kind | grep '"Subnet"' | head -1 | cut -d'"' -f4)
if [ -z "$SUBNET" ]; then
    print_warning "Could not detect subnet, using default 172.18.255.x"
    NETWORK_PREFIX="172.18.255"
else
    # Extract first three octets (e.g., 172.18.0.0/16 -> 172.18)
    NETWORK_PREFIX=$(echo $SUBNET | cut -d'.' -f1-2)".255"
fi

print_status "Configuring MetalLB with network: $NETWORK_PREFIX.200-250"

# Step 6: Configure MetalLB IP pool
kubectl apply -f - <<EOF
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: example
  namespace: metallb-system
spec:
  addresses:
  - $NETWORK_PREFIX.200-$NETWORK_PREFIX.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: empty
  namespace: metallb-system
EOF

# Step 7: Deploy the API
print_status "Deploying API application..."
kubectl apply -f $DEPLOYMENT_FILE

# Step 8: Wait for deployment to be ready
print_status "Waiting for API deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/my-api

# Step 9: Wait for LoadBalancer to get external IP
print_status "Waiting for LoadBalancer to get external IP..."
for i in {1..30}; do
    EXTERNAL_IP=$(kubectl get svc k-api-service -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    if [ -n "$EXTERNAL_IP" ]; then
        break
    fi
    echo "Waiting for external IP... (attempt $i/30)"
    sleep 2
done

# Step 10: Display results
echo
echo "🎉 Cluster rebuild complete!"
echo "=================================="

# Show cluster status
kubectl get nodes
echo

# Show service status
kubectl get svc k-api-service
echo

# Show pod status
kubectl get pods
echo

# Test API if external IP is available
if [ -n "$EXTERNAL_IP" ]; then
    print_status "API is available at: http://$EXTERNAL_IP"
    print_status "Testing API connection..."
    
    if curl -s --max-time 5 "http://$EXTERNAL_IP/api/data" >/dev/null; then
        echo "✅ API is responding!"
        echo
        echo "Test commands:"
        echo "  curl http://$EXTERNAL_IP/api/data"
        echo "  curl -X POST http://$EXTERNAL_IP/api/data -H 'Content-Type: application/json' -d '{\"test\": \"data\"}'"
        echo
        echo "For Burp Suite testing:"
        echo "  curl --proxy 127.0.0.1:8081 http://$EXTERNAL_IP/api/data"
    else
        print_warning "API not responding yet, may need a few more seconds to start"
    fi
else
    print_warning "External IP not assigned yet. Check with: kubectl get svc k-api-service"
fi

echo
print_status "Rebuild complete! 🚀"