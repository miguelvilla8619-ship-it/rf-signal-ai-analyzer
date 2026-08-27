const express = require('express');
const socketIo = require('socket.io');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.API_PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory storage (replace with database in production)
const detectionResults = [];
const scanHistory = [];

// API Endpoints

// Start comprehensive threat scan
app.post('/api/scan/threats', (req, res) => {
  const { location, duration } = req.body;
  
  const scanId = `scan-${Date.now()}`;
  const scan = {
    id: scanId,
    location,
    duration: duration || 300, // 5 minutes default
    startTime: new Date(),
    status: 'running',
    results: null,
  };
  
  scanHistory.push(scan);
  
  res.json({
    success: true,
    scanId,
    message: `Scan started for ${duration || 300} seconds`,
  });
});

// Get scan results
app.get('/api/scan/:scanId', (req, res) => {
  const scan = scanHistory.find(s => s.id === req.params.scanId);
  
  if (!scan) {
    return res.status(404).json({ error: 'Scan not found' });
  }
  
  res.json(scan);
});

// Upload detection data
app.post('/api/detections', (req, res) => {
  const { threatType, data, confidence, timestamp } = req.body;
  
  const detection = {
    id: `detection-${Date.now()}`,
    threatType,
    data,
    confidence,
    timestamp: timestamp || new Date(),
    reviewed: false,
  };
  
  detectionResults.push(detection);
  
  // Broadcast to connected clients
  io.emit('new_detection', detection);
  
  res.json({
    success: true,
    detectionId: detection.id,
  });
});

// Get all threats
app.get('/api/threats', (req, res) => {
  const threatType = req.query.type;
  
  let threats = detectionResults;
  if (threatType) {
    threats = threats.filter(t => t.threatType === threatType);
  }
  
  res.json({
    total: threats.length,
    threats: threats.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)),
  });
});

// Get threats by category
app.get('/api/threats/categories', (req, res) => {
  const categories = {
    hidden_cameras: detectionResults.filter(t => t.threatType === 'camera').length,
    stealth_bluetooth: detectionResults.filter(t => t.threatType === 'bluetooth').length,
    covert_wifi: detectionResults.filter(t => t.threatType === 'wifi').length,
    trackers: detectionResults.filter(t => t.threatType === 'tracker').length,
    drones: detectionResults.filter(t => t.threatType === 'drone').length,
  };
  
  res.json(categories);
});

// Get threat analysis
app.get('/api/analysis/threats', (req, res) => {
  const riskAssessment = {
    critical_threats: detectionResults.filter(t => t.data?.threat_level === 'critical').length,
    high_threats: detectionResults.filter(t => t.data?.threat_level === 'high').length,
    medium_threats: detectionResults.filter(t => t.data?.threat_level === 'medium').length,
    recommendations: [
      'Regular security audits recommended',
      'Enable all available protections',
      'Review network access logs',
      'Update all device firmware',
    ],
  };
  
  res.json(riskAssessment);
});

// Export threat report
app.get('/api/reports/export', (req, res) => {
  const format = req.query.format || 'json';
  
  const report = {
    generatedAt: new Date(),
    totalThreats: detectionResults.length,
    threats: detectionResults,
    summary: {
      cameras: detectionResults.filter(t => t.threatType === 'camera').length,
      bluetooth: detectionResults.filter(t => t.threatType === 'bluetooth').length,
      wifi: detectionResults.filter(t => t.threatType === 'wifi').length,
    },
  };
  
  if (format === 'json') {
    res.json(report);
  } else if (format === 'csv') {
    // Generate CSV
    let csv = 'Type,Confidence,Timestamp,Details\n';
    detectionResults.forEach(t => {
      csv += `"${t.threatType}",${t.confidence},"${t.timestamp}","${JSON.stringify(t.data)}"
`;
    });
    res.type('text/csv').send(csv);
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Initialize Socket.io for real-time updates
const server = require('http').createServer(app);
const io = require('socket.io')(server, {
  cors: { origin: '*' },
});

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Send current threats on connect
  socket.emit('current_threats', detectionResults);
  
  // Listen for scan requests
  socket.on('start_scan', (data) => {
    console.log('Scan requested:', data);
    io.emit('scan_started', { scanId: `scan-${Date.now()}`, ...data });
  });
  
  // Listen for threat updates
  socket.on('threat_detected', (threat) => {
    console.log('Threat detected:', threat);
    io.emit('new_threat', threat);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`🔒 RF Signal Threat Detection API running on port ${PORT}`);
  console.log(`📊 Dashboard available at http://localhost:${PORT}`);
});

module.exports = { app, io };
