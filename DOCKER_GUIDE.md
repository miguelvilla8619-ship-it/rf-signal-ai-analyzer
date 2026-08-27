# RF Signal AI Analyzer - Docker Deployment Guide

## Prerequisites

- Docker Desktop (or Docker Engine + Docker Compose)
- Minimum 4GB RAM available
- 2GB disk space

### Install Docker

**macOS/Windows:**
- Download [Docker Desktop](https://www.docker.com/products/docker-desktop)
- Install and run

**Linux:**
```bash
sudo apt-get install docker.io docker-compose
sudo usermod -aG docker $USER
```

---

## Quick Start

### 1. Start All Services

```bash
# Make script executable
chmod +x start-docker.sh

# Start services
./start-docker.sh
```

OR use docker-compose directly:

```bash
docker-compose up -d
```

### 2. Access Services

- **Backend API:** http://localhost:5000
- **Dashboard:** http://localhost:3000
- **MongoDB:** localhost:27017
- **Redis:** localhost:6379

### 3. Stop Services

```bash
chmod +x stop-docker.sh
./stop-docker.sh
```

OR:

```bash
docker-compose down
```

---

## Docker Services

### Backend (Node.js/Express)
- **Container:** rf-signal-backend
- **Port:** 5000
- **Image:** Custom (Dockerfile.backend)
- **Purpose:** REST API & WebSocket server

### Python Analyzer
- **Container:** rf-signal-analyzer
- **Image:** Custom (Dockerfile.python)
- **Purpose:** Signal scanning & threat analysis

### MongoDB
- **Container:** rf-signal-mongodb
- **Port:** 27017
- **Image:** mongo:7.0
- **Username:** admin
- **Password:** rfSignal2024
- **Database:** rf-signals

### Redis
- **Container:** rf-signal-redis
- **Port:** 6379
- **Image:** redis:7-alpine
- **Purpose:** Caching & real-time data

### Dashboard (React)
- **Container:** rf-signal-dashboard
- **Port:** 3000
- **Image:** Custom (Dockerfile.dashboard)
- **Purpose:** Web UI for threat visualization

---

## Common Commands

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f backend
docker-compose logs -f analyzer
docker-compose logs -f mongodb

# Use log monitoring script
chmod +x logs.sh
./logs.sh
```

### Check Status

```bash
docker-compose ps
```

### Execute Commands Inside Container

```bash
# Backend
docker-compose exec backend node --version

# Python
docker-compose exec analyzer python --version

# MongoDB
docker-compose exec mongodb mongo -u admin -p rfSignal2024 --authenticationDatabase admin
```

### Rebuild Containers

```bash
# Rebuild all
docker-compose build

# Rebuild specific service
docker-compose build backend

# Rebuild and restart
docker-compose up -d --build
```

### View Resource Usage

```bash
docker stats
```

### Clean Up Everything

```bash
chmod +x cleanup-docker.sh
./cleanup-docker.sh

# OR manually
docker-compose down -v  # Remove volumes
docker system prune -a  # Remove unused images
```

---

## Connecting to Services

### API Endpoints

```bash
# Health check
curl http://localhost:5000/api/health

# Get threats
curl http://localhost:5000/api/threats

# Export report
curl http://localhost:5000/api/reports/export?format=csv > threats.csv
```

### MongoDB Connection

```bash
# Connect from host machine
mongo "mongodb://admin:rfSignal2024@localhost:27017/rf-signals?authSource=admin"

# Or from inside container
docker-compose exec mongodb mongo -u admin -p rfSignal2024 --authenticationDatabase admin rf-signals
```

### Redis Connection

```bash
# Connect from host
redis-cli -h localhost -p 6379

# Or from inside container
docker-compose exec redis redis-cli
```

---

## Environment Variables

Edit `.env` file to configure:

```env
NODE_ENV=production
API_PORT=5000
MONGODB_URI=mongodb://admin:rfSignal2024@mongodb:27017/rf-signals
REDIS_URL=redis://redis:6379
FRONTEND_URL=http://localhost:3000
```

---

## Troubleshooting

### Port Already in Use

```bash
# Change port in docker-compose.yml
# For example, use 5001 instead of 5000:
ports:
  - "5001:5000"
```

### Out of Memory

```bash
# Increase Docker memory limit
# Edit Docker Desktop settings or docker-compose.yml:
services:
  backend:
    mem_limit: 2g
```

### MongoDB Won't Start

```bash
# Remove old data
docker-compose down -v
docker-compose up -d mongodb

# Check logs
docker-compose logs mongodb
```

### Services Not Communicating

```bash
# Check network
docker network ls
docker network inspect rf-signal-ai-analyzer_rf-signal-network

# Restart all services
docker-compose restart
```

---

## Performance Tips

1. **Allocate Resources:** Give Docker at least 4GB RAM
2. **Monitor Usage:** Run `docker stats` to check CPU/memory
3. **Enable BuildKit:** `export DOCKER_BUILDKIT=1` for faster builds
4. **Use Alpine Images:** Smaller, faster containers
5. **Prune Regularly:** `docker system prune -a` to clean up

---

## Next Steps

1. ✅ Start Docker services
2. 📊 Access dashboard at http://localhost:3000
3. 🔍 Start scanning via API
4. 📈 Monitor threats in real-time
5. 💾 Data persists in MongoDB

---

## Support

For issues:
1. Check logs: `docker-compose logs -f`
2. Check Docker status: `docker-compose ps`
3. Verify network: `docker network inspect rf-signal-ai-analyzer_rf-signal-network`
4. Review error messages carefully

**Local deployment complete!** 🎉
