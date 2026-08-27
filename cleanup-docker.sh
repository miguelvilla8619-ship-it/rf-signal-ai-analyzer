#!/bin/bash

# Clean up Docker volumes and containers

echo "⚠️  WARNING: This will remove all data!"
echo "Continue? (y/n)"
read -r response

if [ "$response" = "y" ]; then
    echo "Removing containers and volumes..."
    docker-compose down -v
    echo "Cleanup complete."
else
    echo "Cancelled."
fi
