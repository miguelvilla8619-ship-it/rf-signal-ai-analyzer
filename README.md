# RF Signal AI Analyzer - Tracker & Surveillance Detection

Advanced AI-powered system for detecting and analyzing RF signals, wireless trackers, and surveillance devices.

## Features

### Tracker Detection
- **Apple AirTag** - iBeacon protocol detection
- **Samsung SmartTag** - Bluetooth LE scanning
- **Tile Trackers** - Signal signature analysis
- **Chipolo** - Cross-frequency detection
- **Google Find My** - BLE advertisement parsing
- **Clone/Spoof Detection** - Identify counterfeit devices
- **Unregistered Trackers** - Flag unknown beacon sources

### Cross-Platform Detection
- Android Device ID matching
- Google Fast Pair protocol analysis
- iOS/macOS ecosystem tracking
- Smart device fingerprinting
- Ghost device identification (inactive but transmitting)

### Handoff & Relay Detection
- Signal relay pattern recognition
- Handoff sequence identification
- Multi-hop surveillance chains
- Network topology mapping
- Dead zone relay detection

### Drone Signal Detection
- Frequency pattern matching (2.4GHz, 5.8GHz)
- Control signal identification
- Telemetry stream detection
- Flight controller signatures
- Drone model classification

### Pattern Detection & Threat Analysis
- **Follower Detection** - Repeated visitor identification
- **Nighttime Visitors** - After-hours tracking activity
- **Team Surveillance** - Coordinated multi-device tracking
- **Organization Tracking** - Enterprise surveillance patterns
- **Spoofing Attempts** - MAC address and beacon spoofing
- **Activity Anomalies** - Unusual signal behavior

### AI Learning System
- Machine learning device fingerprinting
- Behavioral pattern learning
- Threat classification engine
- Real-time anomaly detection
- Adaptive threat modeling

## Architecture

```
┌─────────────────────────────────────┐
│   RF Signal Data Collection         │
│  (BLE, WiFi, Frequency Analysis)    │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Signal Processing & Filtering     │
│  (Deduplication, Normalization)     │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Tracker Identification Module     │
│  (Signature Matching, ML Classifier)│
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Pattern & Behavior Analysis       │
│  (Movement, Handoff, Relays)        │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Threat Assessment Engine          │
│  (AI-Powered Risk Scoring)          │
└────────────────┬────────────────────┘
                 │
┌────────────────▼────────────────────┐
│   Alert & Reporting System          │
│  (Real-time Notifications)          │
└─────────────────────────────────────┘
```

## Tech Stack

- **AI/ML**: TensorFlow, PyTorch, scikit-learn
- **Signal Processing**: GNU Radio, pyrtlsdr
- **Backend**: Python, Node.js/Express
- **Database**: PostgreSQL, Redis
- **Real-time**: WebSocket, Socket.io
- **Visualization**: D3.js, Plotly
- **Deployment**: Docker, Kubernetes

## Installation

```bash
git clone https://github.com/miguelvilla8619-ship-it/rf-signal-ai-analyzer.git
cd rf-signal-ai-analyzer

# Install dependencies
pip install -r requirements.txt
npm install

# Start services
python main.py
node server.js
```

## Usage

```python
from signal_analyzer import RFAnalyzer, ThreatDetector

# Initialize analyzer
analyzer = RFAnalyzer()
detector = ThreatDetector()

# Scan for signals
signals = analyzer.scan_environment()

# Identify trackers
trackers = detector.identify_trackers(signals)

# Analyze patterns
patterns = detector.analyze_patterns(signals, time_window=3600)

# Assess threat level
threats = detector.assess_threats(patterns)
```

## Supported Protocols

- Bluetooth Low Energy (BLE)
- Bluetooth Classic
- WiFi (802.11)
- Zigbee
- Z-Wave
- Thread
- LoRaWAN
- NB-IoT
- LTE-M
- Proprietary drone protocols (DJI, Parrot, etc.)

## Threat Levels

- **Critical** - Active coordinated surveillance
- **High** - Persistent tracker with movement correlation
- **Medium** - Unknown device with suspicious behavior
- **Low** - Standard consumer devices with normal patterns
- **Info** - Legitimate registered devices

## Privacy & Legal

⚠️ **Important**: This tool is for security research and personal protection only.
- Use only on devices you own or have permission to analyze
- Comply with local RF detection and privacy laws
- Do not use for unauthorized tracking or surveillance
- Respect others' privacy and security

## Contributing

See CONTRIBUTING.md for guidelines

## License

MIT License
