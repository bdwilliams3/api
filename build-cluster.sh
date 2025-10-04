#!/bin/bash

# KIND Cluster Rebuild Script
# This script rebuilds your KIND cluster with API deployment and MetalLB

set -e  # Exit on any error

CLUSTER_NAME="api-cluster"
IMAGE_NAME="api:latest"
CONFIG_FILE="kind-config.yaml"
DEPLOYMENT_FILE="deployment.yaml"
HOSTNAME_ALIAS="kube-api-test"
FORWARD_PORT="3000"

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

# Function to add/update hosts entry
update_hosts_file() {
    local hostname="$1"
    local hosts_file
    
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        hosts_file="C:/Windows/System32/drivers/etc/hosts"
    else
        hosts_file="/etc/hosts"
    fi
    
    print_status "Updating hosts file with $hostname..."
    
    # Remove existing entry if it exists
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        # Windows - requires admin privileges
        powershell -Command "
            \$hostsFile = 'C:\Windows\System32\drivers\etc\hosts'
            \$content = Get-Content \$hostsFile | Where-Object { \$_ -notmatch '$hostname' }
            \$content += '127.0.0.1 $hostname'
            Set-Content -Path \$hostsFile -Value \$content
        " 2>/dev/null || print_warning "Could not update hosts file automatically. Please add '127.0.0.1 $hostname' to $hosts_file manually"
    else
        # Linux/Mac
        if sudo grep -q "$hostname" "$hosts_file" 2>/dev/null; then
            sudo sed -i "/$hostname/d" "$hosts_file"
        fi
        echo "127.0.0.1 $hostname" | sudo tee -a "$hosts_file" >/dev/null || {
            print_warning "Could not update hosts file automatically."
            print_warning "Please add the following line to $hosts_file:"
            echo "127.0.0.1 $hostname"
        }
    fi
}

# Function to start port forwarding in background
start_port_forward() {
    local service_name="$1"
    local forward_port="$2"
    local target_port="$3"
    
    print_status "Starting port forwarding: localhost:$forward_port -> $service_name:$target_port"
    
    # Kill any existing port forwarding on this port
    pkill -f "kubectl.*port-forward.*:$forward_port" 2>/dev/null || true
    
    # Start port forwarding in background
    kubectl port-forward service/$service_name $forward_port:$target_port &
    PORT_FORWARD_PID=$!
    
    # Wait a moment for port forwarding to establish
    sleep 2
    
    # Check if port forwarding is working
    if kill -0 $PORT_FORWARD_PID 2>/dev/null; then
        print_status "Port forwarding established (PID: $PORT_FORWARD_PID)"
        echo $PORT_FORWARD_PID > /tmp/kubectl-port-forward.pid
    else
        print_error "Port forwarding failed to start"
        return 1
    fi
}

# Check if required files exist
if [ ! -f "$CONFIG_FILE" ]; then
    print_error "kind-config.yaml not found!"
    exit 1
fi

if [ ! -f "$DEPLOYMENT_FILE" ]; then
    print_error "deployment.yaml not found!"
    exit 1
fi

# Clean up existing cluster if it exists
if kind get clusters | grep -q "$CLUSTER_NAME"; then
    print_warning "Deleting existing cluster: $CLUSTER_NAME"
    kind delete cluster --name=$CLUSTER_NAME
fi

# Step 1: Build Docker image
print_status "Building Docker image..."
docker build -t $IMAGE_NAME .

# Step 2: Create KIND cluster
print_status "Creating KIND cluster..."
kind create cluster --config=$CONFIG_FILE --name=$CLUSTER_NAME

# Step 3: Load Docker image into KIND cluster
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
kubectl wait --for=condition=available --timeout=300s deployment/k-api

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

# Step 10: Update hosts file
update_hosts_file "$HOSTNAME_ALIAS"

# Step 11: Start port forwarding
# Detect the target port from the service
TARGET_PORT=$(kubectl get svc k-api-service -o jsonpath='{.spec.ports[0].port}')
if [ -z "$TARGET_PORT" ]; then
    TARGET_PORT="80"  # Default fallback
fi

start_port_forward "k-api-service" "$FORWARD_PORT" "$TARGET_PORT"

# Step 12: Display results
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
    print_status "API is available at:"
    echo "  • Internal cluster: http://$EXTERNAL_IP"
    echo "  • External access:  http://$HOSTNAME_ALIAS:$FORWARD_PORT"
    echo
    
    print_status "Testing API connection via port forward..."
    
    # Wait a bit more for the API to be fully ready
    sleep 3
    
    if curl -s --max-time 10 "http://localhost:$FORWARD_PORT/api/data" >/dev/null; then
        echo "✅ API is responding via port forward!"
        echo
        echo "🌐 Browser URLs:"
        echo "  http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data"
        echo "  http://localhost:$FORWARD_PORT/api/data"
        echo
        echo "🧪 Test commands:"
        echo "  curl http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data"
        echo "  curl -X POST http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data -H 'Content-Type: application/json' -d '{\"test\": \"data\"}'"
        echo
        echo "🔍 For Burp Suite testing:"
        echo "  curl --proxy 127.0.0.1:8080 http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data"
        echo
        echo "📋 To stop port forwarding later:"
        echo "  pkill -f \"kubectl.*port-forward.*:$FORWARD_PORT\""
    else
        print_warning "API not responding via port forward yet, may need a few more seconds to start"
        echo "Try manually: curl http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data"
    fi
else
    print_warning "External IP not assigned yet. Check with: kubectl get svc k-api-service"
    echo "But you can still access via: http://$HOSTNAME_ALIAS:$FORWARD_PORT"
fi

echo
echo "🎯 Ready for browser testing at: http://$HOSTNAME_ALIAS:$FORWARD_PORT/api/data"
print_status "Rebuild complete! 🚀"

# Keep the script running to maintain port forwarding
if [ -n "$PORT_FORWARD_PID" ] && kill -0 $PORT_FORWARD_PID 2>/dev/null; then
    echo
    print_status "Port forwarding is active. Press Ctrl+C to stop and cleanup."
    
    # Setup cleanup on exit
    cleanup() {
        echo
        print_status "Cleaning up..."
        kill $PORT_FORWARD_PID 2>/dev/null || true
        rm -f /tmp/kubectl-port-forward.pid
        print_status "Port forwarding stopped."
        exit 0
    }
    
    trap cleanup SIGINT SIGTERM
    
    # Wait for interrupt
    wait $PORT_FORWARD_PID
fi