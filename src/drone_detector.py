import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class DroneDetector:
    """Detects drone signals and identifies drone models."""
    
    # Common drone control frequencies
    DRONE_FREQUENCIES = {
        '2.4GHz': [2400, 2500],  # WiFi-based drones (DJI, Parrot)
        '5.8GHz': [5725, 5850],  # FPV and high-end drones
        '900MHz': [900, 950],    # Long-range control
        'LTE': [700, 2600],      # Cellular drones
    }
    
    # Drone manufacturer signatures
    DRONE_SIGNATURES = {
        'dji': {
            'manufacturer_id': 0x27F7,
            'beacon_pattern': r'DJI',
            'frequency_bands': ['2.4GHz', '5.8GHz'],
            'telemetry_ports': [55935, 55936],
            'models': ['Phantom', 'Mavic', 'Air', 'Mini', 'Avata'],
        },
        'parrot': {
            'manufacturer_id': 0x0900,
            'beacon_pattern': r'Parrot',
            'frequency_bands': ['2.4GHz', '5.8GHz'],
            'telemetry_ports': [43210],
            'models': ['AR.Drone', 'Bebop', 'Anafi'],
        },
        'yuneec': {
            'manufacturer_id': 0x0460,
            'beacon_pattern': r'Yuneec',
            'frequency_bands': ['2.4GHz', '5.8GHz'],
            'models': ['Typhoon', 'Breeze'],
        },
        'auterls': {
            'manufacturer_id': 0x2700,
            'beacon_pattern': r'Auterls',
            'frequency_bands': ['2.4GHz'],
            'models': ['X-Star', 'X-Pro'],
        },
        'skydio': {
            'manufacturer_id': 0x4653,
            'beacon_pattern': r'Skydio',
            'frequency_bands': ['2.4GHz'],
            'models': ['X2', 'X2E', 'X2D'],
        },
    }
    
    def __init__(self):
        self.detected_drones = {}
        self.flight_paths = defaultdict(list)
        self.signal_patterns = defaultdict(list)
    
    def detect_drones(self, signals: List[Dict]) -> List[Dict]:
        """Identify drone signals from detected RF signals."""
        detected = []
        
        for signal in signals:
            drone_info = self._identify_drone(signal)
            if drone_info['is_drone']:
                drone_info['signal'] = signal
                detected.append(drone_info)
                self.detected_drones[signal['signal_id']] = drone_info
        
        return detected
    
    def _identify_drone(self, signal: Dict) -> Dict:
        """Identify if signal is from a drone."""
        result = {
            'is_drone': False,
            'manufacturer': None,
            'model': None,
            'confidence': 0.0,
            'characteristics': [],
        }
        
        # Check frequency
        if self._is_drone_frequency(signal.get('frequency')):
            result['characteristics'].append('drone_frequency')
            result['confidence'] += 0.3
        
        # Check manufacturer signature
        manufacturer = self._check_manufacturer_signature(signal)
        if manufacturer:
            result['manufacturer'] = manufacturer
            result['characteristics'].append('manufacturer_signature')
            result['confidence'] += 0.4
        
        # Check beacon pattern
        beacon_match = self._check_beacon_pattern(signal)
        if beacon_match:
            result['characteristics'].append('beacon_pattern')
            result['confidence'] += 0.2
        
        # Check for telemetry signals
        if self._detect_telemetry(signal):
            result['characteristics'].append('telemetry_detected')
            result['confidence'] += 0.15
        
        # Check control signal patterns
        if self._detect_control_signals(signal):
            result['characteristics'].append('control_signal')
            result['confidence'] += 0.1
        
        result['is_drone'] = result['confidence'] >= 0.5
        
        # Attempt to identify specific model
        if result['manufacturer']:
            result['model'] = self._identify_model(signal, result['manufacturer'])
        
        return result
    
    def _is_drone_frequency(self, frequency: float) -> bool:
        """Check if frequency is in drone control band."""
        for band, freq_range in self.DRONE_FREQUENCIES.items():
            if freq_range[0] <= frequency <= freq_range[1]:
                return True
        return False
    
    def _check_manufacturer_signature(self, signal: Dict) -> str:
        """Match signal to known drone manufacturer."""
        manufacturer_id = signal.get('manufacturer_id')
        
        for mfg_name, signature in self.DRONE_SIGNATURES.items():
            if manufacturer_id == signature.get('manufacturer_id'):
                return mfg_name
        
        return None
    
    def _check_beacon_pattern(self, signal: Dict) -> bool:
        """Check for drone manufacturer beacon patterns."""
        device_name = signal.get('device_name', '')
        
        for mfg_name, signature in self.DRONE_SIGNATURES.items():
            pattern = signature.get('beacon_pattern')
            if pattern and pattern.lower() in device_name.lower():
                return True
        
        return False
    
    def _detect_telemetry(self, signal: Dict) -> bool:
        """Detect drone telemetry transmissions."""
        port = signal.get('port')
        packet_pattern = signal.get('packet_pattern')
        
        for mfg_name, signature in self.DRONE_SIGNATURES.items():
            telemetry_ports = signature.get('telemetry_ports', [])
            if port in telemetry_ports:
                return True
        
        # Check packet structure for telemetry
        if packet_pattern and len(packet_pattern) > 100:
            return True
        
        return False
    
    def _detect_control_signals(self, signal: Dict) -> bool:
        """Detect drone remote control signals."""
        # Control signals typically have:
        # - Consistent transmission intervals (5-20ms)
        # - Payload size 16-64 bytes
        # - RC channel data (throttle, roll, pitch, yaw)
        
        interval = signal.get('transmission_interval')
        payload_size = signal.get('payload_size', 0)
        
        if interval and 5 <= interval <= 20:  # milliseconds
            if 16 <= payload_size <= 64:
                return True
        
        return False
    
    def _identify_model(self, signal: Dict, manufacturer: str) -> str:
        """Attempt to identify specific drone model."""
        signature = self.DRONE_SIGNATURES.get(manufacturer, {})
        device_name = signal.get('device_name', '').lower()
        
        for model in signature.get('models', []):
            if model.lower() in device_name:
                return model
        
        # Try to infer from frequency and power
        if signal.get('rssi', -100) > -60:  # Strong signal
            return 'High-End Model (Mavic/Phantom)'
        else:
            return 'Budget Model (Mini/Air)'
    
    def track_flight_path(self, drone_id: str, position: Tuple[float, float], 
                         timestamp: datetime) -> Dict:
        """Track drone flight path over time."""
        self.flight_paths[drone_id].append({
            'position': position,
            'timestamp': timestamp,
        })
        
        # Analyze flight pattern
        if len(self.flight_paths[drone_id]) > 2:
            return self._analyze_flight_pattern(drone_id)
        
        return {'drone_id': drone_id, 'pattern': None}
    
    def _analyze_flight_pattern(self, drone_id: str) -> Dict:
        """Analyze drone flight pattern for surveillance indicators."""
        path = self.flight_paths[drone_id]
        
        # Calculate key metrics
        total_distance = self._calculate_path_distance(path)
        max_altitude = max(p['position'][2] for p in path if len(p['position']) > 2) if any(len(p['position']) > 2 for p in path) else 0
        flight_duration = (path[-1]['timestamp'] - path[0]['timestamp']).total_seconds()
        
        # Detect surveillance patterns
        is_hovering = self._detect_hovering(path)
        is_circling = self._detect_circling(path)
        is_tracking = self._detect_tracking_pattern(path)
        
        threat_level = 'low'
        if is_tracking:
            threat_level = 'high'
        elif is_circling or is_hovering:
            threat_level = 'medium'
        
        return {
            'drone_id': drone_id,
            'total_distance': total_distance,
            'max_altitude': max_altitude,
            'flight_duration': flight_duration,
            'hovering': is_hovering,
            'circling': is_circling,
            'tracking_pattern': is_tracking,
            'threat_level': threat_level,
        }
    
    def _calculate_path_distance(self, path: List[Dict]) -> float:
        """Calculate total distance traveled."""
        if len(path) < 2:
            return 0
        
        total = 0
        for i in range(len(path) - 1):
            pos1 = path[i]['position']
            pos2 = path[i+1]['position']
            distance = np.sqrt(sum((p1 - p2)**2 for p1, p2 in zip(pos1, pos2)))
            total += distance
        
        return total
    
    def _detect_hovering(self, path: List[Dict]) -> bool:
        """Detect if drone is hovering in place."""
        if len(path) < 10:
            return False
        
        # Check last 10 points for minimal movement
        recent = path[-10:]
        distances = []
        
        for i in range(len(recent) - 1):
            pos1 = recent[i]['position']
            pos2 = recent[i+1]['position']
            distance = np.sqrt(sum((p1 - p2)**2 for p1, p2 in zip(pos1[:2], pos2[:2])))
            distances.append(distance)
        
        avg_distance = np.mean(distances)
        return avg_distance < 5  # Less than 5 meters movement
    
    def _detect_circling(self, path: List[Dict]) -> bool:
        """Detect if drone is circling location."""
        if len(path) < 20:
            return False
        
        # Analyze position angles from center
        positions = [p['position'][:2] for p in path[-20:]]
        center = np.mean(positions, axis=0)
        
        angles = []
        for pos in positions:
            angle = np.arctan2(pos[1] - center[1], pos[0] - center[0])
            angles.append(angle)
        
        # Check if angles show circular pattern (covering full 360 degrees)
        angle_range = np.max(angles) - np.min(angles)
        return angle_range > 6  # > 6 radians ≈ full circle
    
    def _detect_tracking_pattern(self, path: List[Dict]) -> bool:
        """Detect if drone follows a target."""
        if len(path) < 15:
            return False
        
        # Analyze recent movements for consistent tracking direction
        recent = path[-15:]
        velocities = []
        
        for i in range(len(recent) - 1):
            time_diff = (recent[i+1]['timestamp'] - recent[i]['timestamp']).total_seconds()
            if time_diff == 0:
                continue
            
            pos1 = recent[i]['position'][:2]
            pos2 = recent[i+1]['position'][:2]
            velocity = (np.array(pos2) - np.array(pos1)) / time_diff
            velocities.append(velocity)
        
        if not velocities:
            return False
        
        # Check velocity consistency (tracking maintains direction)
        velocities = np.array(velocities)
        velocity_variance = np.var(velocities)
        
        return velocity_variance < 5  # Low variance = consistent tracking
