import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Tuple
import logging

logger = logging.getLogger(__name__)

class PatternAnalyzer:
    """Analyzes behavioral patterns in signal data."""
    
    def __init__(self, time_window_hours: int = 24):
        self.time_window = timedelta(hours=time_window_hours)
        self.visit_history = defaultdict(list)
        self.movement_patterns = defaultdict(list)
    
    def detect_followers(self, signals: List[Dict], location_data: List[Dict]) -> List[Dict]:
        """Identify persistent trackers following the target."""
        followers = []
        
        # Analyze co-location patterns
        for i, location in enumerate(location_data):
            # Find all devices near this location at this time
            nearby_devices = self._find_nearby_devices(signals, location)
            
            # Track devices that appear at multiple locations in sequence
            for device in nearby_devices:
                self._update_visit_history(device, location)
        
        # Identify devices with high correlation to target movement
        for device, visits in self.visit_history.items():
            if len(visits) >= 3:  # Appears at 3+ target locations
                correlation = self._calculate_movement_correlation(device, location_data)
                if correlation > 0.7:  # High correlation
                    followers.append({
                        'device_id': device,
                        'type': 'follower',
                        'visit_count': len(visits),
                        'correlation_score': correlation,
                        'threat_level': 'high',
                        'visits': visits,
                    })
        
        return followers
    
    def detect_nighttime_visitors(self, signals: List[Dict], 24_hour_log: Dict) -> List[Dict]:
        """Identify devices appearing during unusual hours (nighttime)."""
        nighttime_visitors = []
        
        for device_id, signal_log in 24_hour_log.items():
            nighttime_signals = []
            daytime_signals = []
            
            for signal in signal_log:
                hour = signal['timestamp'].hour
                
                # Define nighttime as 10 PM to 6 AM
                if hour >= 22 or hour < 6:
                    nighttime_signals.append(signal)
                else:
                    daytime_signals.append(signal)
            
            # Flag devices that appear primarily at night
            if len(nighttime_signals) > len(daytime_signals) and len(nighttime_signals) >= 3:
                nighttime_visitors.append({
                    'device_id': device_id,
                    'type': 'nighttime_visitor',
                    'nighttime_detections': len(nighttime_signals),
                    'daytime_detections': len(daytime_signals),
                    'threat_level': 'high',
                    'signals': nighttime_signals,
                })
        
        return nighttime_visitors
    
    def detect_team_surveillance(self, signals: List[Dict]) -> List[Dict]:
        """Identify coordinated multi-device surveillance patterns."""
        surveillance_teams = []
        time_window = timedelta(minutes=5)
        
        # Group signals by time windows
        time_groups = defaultdict(list)
        for signal in signals:
            time_bucket = signal['timestamp'].replace(second=0, microsecond=0)
            time_groups[time_bucket].append(signal)
        
        # Identify time windows with multiple devices
        for time_bucket, group in time_groups.items():
            if len(set(s['device_id'] for s in group)) >= 3:  # 3+ different devices
                # Check if devices appear to be coordinated
                team = {
                    'timestamp': time_bucket,
                    'device_count': len(set(s['device_id'] for s in group)),
                    'devices': list(set(s['device_id'] for s in group)),
                    'type': 'team_surveillance',
                    'threat_level': 'critical',
                    'signals': group,
                }
                surveillance_teams.append(team)
        
        return surveillance_teams
    
    def detect_repeat_visitors(self, location_history: List[Dict], 
                              repeat_threshold: int = 3) -> List[Dict]:
        """Identify devices that repeatedly visit same location."""
        repeat_visitors = []
        location_device_map = defaultdict(lambda: defaultdict(int))
        
        # Count device visits per location
        for record in location_history:
            location = record['location']
            device_id = record['device_id']
            location_device_map[location][device_id] += 1
        
        # Find devices with repeat visits
        for location, devices in location_device_map.items():
            for device_id, visit_count in devices.items():
                if visit_count >= repeat_threshold:
                    repeat_visitors.append({
                        'device_id': device_id,
                        'location': location,
                        'visit_count': visit_count,
                        'type': 'repeat_visitor',
                        'threat_level': 'medium',
                    })
        
        return repeat_visitors
    
    def _find_nearby_devices(self, signals: List[Dict], location: Dict) -> List[str]:
        """Find devices near a specific location."""
        nearby = []
        location_threshold = 100  # meters
        
        for signal in signals:
            if 'location' in signal:
                distance = self._calculate_distance(
                    location['coordinates'],
                    signal['location']['coordinates']
                )
                if distance < location_threshold:
                    nearby.append(signal['device_id'])
        
        return nearby
    
    def _update_visit_history(self, device_id: str, location: Dict):
        """Record device visit to location."""
        self.visit_history[device_id].append({
            'location': location,
            'timestamp': datetime.now(),
        })
    
    def _calculate_movement_correlation(self, device_id: str, target_locations: List[Dict]) -> float:
        """Calculate how closely device movement correlates with target."""
        if device_id not in self.visit_history:
            return 0.0
        
        device_visits = self.visit_history[device_id]
        matches = 0
        
        for visit in device_visits:
            for target_location in target_locations:
                distance = self._calculate_distance(
                    visit['location']['coordinates'],
                    target_location['coordinates']
                )
                if distance < 50:  # Within 50 meters
                    matches += 1
        
        return matches / len(device_visits) if device_visits else 0.0
    
    def _calculate_distance(self, coord1: Tuple[float, float], 
                           coord2: Tuple[float, float]) -> float:
        """Calculate distance between two coordinates in meters."""
        # Simplified distance calculation (use proper geospatial library for accuracy)
        lat1, lon1 = coord1
        lat2, lon2 = coord2
        
        # Haversine formula approximation
        dlat = abs(lat2 - lat1) * 111000  # 1 degree latitude ≈ 111 km
        dlon = abs(lon2 - lon1) * 111000 * np.cos(np.radians((lat1 + lat2) / 2))
        
        return np.sqrt(dlat**2 + dlon**2)


class ThreatDetector:
    """AI-powered threat assessment and detection."""
    
    def __init__(self):
        self.pattern_analyzer = PatternAnalyzer()
        self.threat_model = self._initialize_threat_model()
        self.alert_history = []
    
    def assess_threats(self, signals: List[Dict], 
                      location_data: List[Dict] = None) -> List[Dict]:
        """Comprehensive threat assessment of detected signals."""
        threats = []
        
        # Analyze multiple threat vectors
        tracker_threats = self._assess_tracker_threats(signals)
        pattern_threats = self._assess_pattern_threats(signals, location_data)
        drone_threats = self._assess_drone_threats(signals)
        network_threats = self._assess_network_threats(signals)
        
        threats.extend(tracker_threats)
        threats.extend(pattern_threats)
        threats.extend(drone_threats)
        threats.extend(network_threats)
        
        # Sort by severity
        threats.sort(key=lambda x: x['threat_score'], reverse=True)
        
        return threats
    
    def _assess_tracker_threats(self, signals: List[Dict]) -> List[Dict]:
        """Assess threats from known tracking devices."""
        threats = []
        
        for signal in signals:
            if signal.get('is_tracker'):
                threat_score = self._calculate_threat_score(signal)
                if threat_score > 0.5:
                    threats.append({
                        'type': 'tracker',
                        'device_id': signal['device_id'],
                        'tracker_type': signal.get('tracker_type'),
                        'threat_score': threat_score,
                        'threat_level': self._score_to_level(threat_score),
                        'description': f"Known tracker detected: {signal.get('tracker_type')}",
                    })
        
        return threats
    
    def _assess_pattern_threats(self, signals: List[Dict], 
                                location_data: List[Dict]) -> List[Dict]:
        """Assess threats from suspicious behavioral patterns."""
        threats = []
        
        if not location_data:
            return threats
        
        # Detect followers
        followers = self.pattern_analyzer.detect_followers(signals, location_data)
        for follower in followers:
            threats.append({
                'type': 'behavioral_threat',
                'subtype': 'follower',
                'device_id': follower['device_id'],
                'threat_score': 0.85,
                'threat_level': 'high',
                'description': f"Device follows movement pattern (correlation: {follower['correlation_score']:.2%})",
            })
        
        # Detect nighttime visitors
        nighttime = self.pattern_analyzer.detect_nighttime_visitors(signals, {})
        for visitor in nighttime:
            threats.append({
                'type': 'behavioral_threat',
                'subtype': 'nighttime_visitor',
                'device_id': visitor['device_id'],
                'threat_score': 0.75,
                'threat_level': 'high',
                'description': f"Device appears primarily at night",
            })
        
        # Detect team surveillance
        teams = self.pattern_analyzer.detect_team_surveillance(signals)
        for team in teams:
            threats.append({
                'type': 'behavioral_threat',
                'subtype': 'team_surveillance',
                'device_count': team['device_count'],
                'threat_score': 0.95,
                'threat_level': 'critical',
                'description': f"Coordinated surveillance detected ({team['device_count']} devices)",
            })
        
        return threats
    
    def _assess_drone_threats(self, signals: List[Dict]) -> List[Dict]:
        """Assess threats from detected drones."""
        threats = []
        
        for signal in signals:
            if signal.get('device_type') == 'drone':
                drone_confidence = signal.get('confidence', 0.5)
                threat_score = 0.8 * drone_confidence
                
                threats.append({
                    'type': 'drone',
                    'device_id': signal['device_id'],
                    'drone_model': signal.get('drone_model', 'Unknown'),
                    'threat_score': threat_score,
                    'threat_level': 'high',
                    'description': f"Drone detected: {signal.get('drone_model')}",
                })
        
        return threats
    
    def _assess_network_threats(self, signals: List[Dict]) -> List[Dict]:
        """Assess threats from network-based attacks or relay chains."""
        threats = []
        
        # Check for relay chains
        relay_count = defaultdict(int)
        for signal in signals:
            if signal.get('is_relay'):
                relay_count[signal['relay_group']] += 1
        
        for relay_group, count in relay_count.items():
            if count >= 3:
                threat_score = min(0.9, 0.6 + (count * 0.1))
                threats.append({
                    'type': 'network_threat',
                    'subtype': 'relay_chain',
                    'relay_count': count,
                    'threat_score': threat_score,
                    'threat_level': 'high',
                    'description': f"Relay chain detected ({count} devices)",
                })
        
        return threats
    
    def _calculate_threat_score(self, signal: Dict) -> float:
        """Calculate threat score for a signal using ML model."""
        score = 0.5  # Base score
        
        # Factors that increase threat score
        if signal.get('is_tracker'):
            score += 0.2
        if signal.get('is_suspicious'):
            score += 0.15
        if signal.get('rssi', -100) > -60:  # Strong signal
            score += 0.1
        if signal.get('is_clone'):
            score += 0.3
        
        return min(1.0, score)
    
    def _score_to_level(self, score: float) -> str:
        """Convert threat score to threat level."""
        if score >= 0.9:
            return 'critical'
        elif score >= 0.7:
            return 'high'
        elif score >= 0.5:
            return 'medium'
        elif score >= 0.3:
            return 'low'
        else:
            return 'info'
    
    def _initialize_threat_model(self):
        """Initialize ML threat classification model."""
        # Placeholder for ML model initialization
        # In production, would load pre-trained TensorFlow/PyTorch model
        return {
            'model_type': 'ensemble',
            'version': '1.0',
            'features': ['rssi', 'device_type', 'frequency', 'tx_power', 'movement_pattern'],
        }
