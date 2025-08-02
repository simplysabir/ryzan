#!/bin/bash

# Ryzan Docker Runner Script
# Usage: ./docker-run.sh [command] [args...]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if docker compose is available
if ! docker compose version &> /dev/null; then
    print_error "docker compose is not available. Please install Docker Compose first."
    exit 1
fi

# Function to build the image
build_image() {
    print_status "Building Ryzan Docker image..."
    docker build -t ryzan:latest .
    print_success "Image built successfully!"
}

# Function to run the container
run_container() {
    local args="$@"
    
    if [ -z "$args" ]; then
        print_status "Starting Ryzan in interactive mode..."
        docker run -it --rm \
            -v ryzan_config:/home/ryzan/.config/ryzan \
            ryzan:latest
    else
        print_status "Running: ryzan $args"
        docker run -it --rm \
            -v ryzan_config:/home/ryzan/.config/ryzan \
            ryzan:latest $args
    fi
}

# Function to start with docker compose
start_compose() {
    print_status "Starting Ryzan with docker compose..."
    docker compose up -d
    print_success "Ryzan is running in the background!"
    print_status "Use 'docker compose exec ryzan ryzan --help' to run commands"
}

# Function to stop docker compose
stop_compose() {
    print_status "Stopping Ryzan..."
    docker compose down
    print_success "Ryzan stopped!"
}

# Function to show logs
show_logs() {
    docker compose logs -f
}

# Function to access shell
access_shell() {
    print_status "Accessing container shell..."
    docker compose exec ryzan bash
}

# Main script logic
case "${1:-}" in
    "build")
        build_image
        ;;
    "run")
        shift
        run_container "$@"
        ;;
    "start")
        start_compose
        ;;
    "stop")
        stop_compose
        ;;
    "restart")
        stop_compose
        start_compose
        ;;
    "logs")
        show_logs
        ;;
    "shell")
        access_shell
        ;;
    "help"|"--help"|"-h")
        echo "Ryzan Docker Runner"
        echo ""
        echo "Usage: $0 [command] [args...]"
        echo ""
        echo "Commands:"
        echo "  build                    Build the Docker image"
        echo "  run [args...]           Run ryzan with optional arguments"
        echo "  start                   Start with docker-compose"
        echo "  stop                    Stop docker-compose"
        echo "  restart                 Restart docker-compose"
        echo "  logs                    Show docker-compose logs"
        echo "  shell                   Access container shell"
        echo "  help                    Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0 build"
        echo "  $0 run --help"
        echo "  $0 run create --name mywallet"
        echo "  $0 start"
        echo "  $0 shell"
        ;;
    "")
        # Default: run interactively
        run_container
        ;;
    *)
        # Pass all arguments to ryzan
        run_container "$@"
        ;;
esac 