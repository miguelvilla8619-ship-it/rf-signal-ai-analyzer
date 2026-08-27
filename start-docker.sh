#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  RF Signal AI Analyzer - Docker Setup${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${YELLOW}❌ Docker is not installed. Please install Docker first.${NC}"
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}❌ Docker Compose is not installed.${NC}"
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose are installed${NC}"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${YELLOW}⚠️  .env file not found. Creating from template...${NC}"
    cp .env.example .env
    echo -e "${GREEN}✓ Created .env file${NC}"
fi

echo ""
echo -e "${BLUE}Building Docker images...${NC}"
docker-compose build

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Build successful${NC}"
else
    echo -e "${YELLOW}❌ Build failed${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}Starting services...${NC}"
docker-compose up -d

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Services started${NC}"
else
    echo -e "${YELLOW}❌ Failed to start services${NC}"
    exit 1
fi

# Wait for services to be ready
echo ""
echo -e "${BLUE}Waiting for services to be ready...${NC}"
sleep 5

# Check service status
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Services Running:${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"

echo -e "${GREEN}Backend API:${NC}       http://localhost:5000"
echo -e "${GREEN}Dashboard:${NC}         http://localhost:3000"
echo -e "${GREEN}MongoDB:${NC}           localhost:27017"
echo -e "${GREEN}Redis:${NC}             localhost:6379"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}Useful Commands:${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo "docker-compose logs -f backend    # View backend logs"
echo "docker-compose logs -f analyzer   # View analyzer logs"
echo "docker-compose stop               # Stop all services"
echo "docker-compose down               # Stop and remove services"
echo "docker-compose ps                 # Show running services"
echo ""
echo -e "${GREEN}Setup complete! 🎉${NC}"
