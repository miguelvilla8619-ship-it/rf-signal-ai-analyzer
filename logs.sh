#!/bin/bash

# Monitor Docker logs for all services

echo "Monitoring RF Signal AI Analyzer..."
echo "Press Ctrl+C to stop"
echo ""

docker-compose logs -f
