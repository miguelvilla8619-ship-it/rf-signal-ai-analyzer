import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)

class RFSignal:
    """Represents a single RF signal detection."""
    
    def __init__(self, signal_id: str, frequency: float, rssi: float, 
                 mac_address: str, device_type: str, timestamp: datetime):
        self.signal_id = signal_id
        self.frequency = frequency
        self.rssi = rssi
        self.mac_address = mac_address
        self.device_type = device_type
        self.timestamp = timestamp
        self.location = None
        self.movement_vector = None

class TrackerIdentifier:
    """Identifies known tracker devices by signature."""
    
    # Device signatures based on BLE advertisement patterns
    TRACKER_SIGNATURES = {
        'apple_airtag': {
            'manufacturer_id': 0x004c,  # Apple
            'beacon_type': 'iBeacon',
            'uuid_pattern': r'FDA50693-A4E2-4FB1-AFCF-C6EB07647825',
            'tx_power_range': (-59, -40),
        },
        'samsung_smarttag': {
            'manufacturer_id': 0x0075,  # Samsung
            'service_uuids': ['180A'],
            'tx_power_range': (-80, -40),
        },
        'tile_tracker': {
            'manufacturer_id': 0x015D,  # Tile
            'beacon_type': 'proprietary',
            'tx_power_range': (-73, -40),
        },
        'chipolo': {
            'manufacturer_id': 0x00E0,
            'service_uuids': ['FFE0'],
            'tx_power_range': (-75, -40),
        },
        'google_findmy': {
            'manufacturer_id': 0x00E0,
            'beacon_type': 'eddystone',
            'service_uuids': ['FEAA'],
        },
        'ibeacon': {
            'beacon_type': 'iBeacon',
            'uuid_length': 16,
        },
    }
    
    def __init__(self):
        self.known_devices = {}
        self.suspicious_devices = {}
    
    def identify_tracker(self, signal: RFSignal) -> Dict:
        """Identify if signal matches known tracker signatures."""
        result = {
            'signal_id': signal.signal_id,
            'device_type': signal.device_type,
            'matched_trackers': [],
            'confidence_score': 0.0,
            'is_tracker': False,
        }
        
        for tracker_name, signature in self.TRACKER_SIGNATURES.items():
            if self._matches_signature(signal, signature):
                result['matched_trackers'].append(tracker_name)
                result['confidence_score'] = max(result['confidence_score'], 0.85)
                result['is_tracker'] = True
        
        return result
    
    def _matches_signature(self, signal: RFSignal, signature: Dict) -> bool:
        """Check if signal matches tracker signature."""
        # Implement pattern matching logic
        if signal.frequency in [2402, 2480]:  # BLE frequency range
            return True
        return False
    
    def detect_clones(self, signals: List[RFSignal]) -> List[Dict]:
        """Detect cloned or spoofed tracker devices."""
        mac_groups = defaultdict(list)
        clones = []
        
        # Group signals by MAC address
        for signal in signals:
            mac_groups[signal.mac_address].append(signal)
        
        # Analyze each MAC address group
        for mac, group in mac_groups.items():
            if len(group) > 1:
                # Check for impossible movement patterns
                if self._detect_impossible_movement(group):
                    clones.append({
                        'mac_address': mac,
                        'type': 'movement_clone',
                        'signals': group,
                        'confidence': 0.9,
                    })
                
                # Check for simultaneous transmissions
                if self._detect_simultaneous_transmission(group):
                    clones.append({
                        'mac_address': mac,
                        'type': 'simultaneous_spoof',
                        'signals': group,
                        'confidence': 0.95,
                    })
        
        return clones
    
    def _detect_impossible_movement(self, signals: List[RFSignal]) -> bool:
        """Check for movement patterns that violate physics."""
        if len(signals) < 2:
            return False
        
        # Calculate distances between consecutive signals
        for i in range(len(signals) - 1):
            time_diff = (signals[i+1].timestamp - signals[i].timestamp).total_seconds()
            if time_diff <= 0:
                continue
            
            # Maximum human speed ~10 m/s, but also check for impossible instantaneous jumps
            if self._calculate_distance(signals[i], signals[i+1]) / time_diff > 50:  # 50 m/s = 180 km/h
                return True
        
        return False
    
    def _detect_simultaneous_transmission(self, signals: List[RFSignal]) -> bool:
        """Detect if same device transmits from multiple locations simultaneously."""
        time_groups = defaultdict(list)
        
        # Group signals within 1 second windows
        for signal in signals:
            time_bucket = signal.timestamp.replace(microsecond=0)
            time_groups[time_bucket].append(signal)
        
        # Check for simultaneous transmissions from different locations
        for time_bucket, group in time_groups.items():
            if len(group) > 1:
                locations = [s.location for s in group if s.location]
                if len(set(locations)) > 1:
                    return True
        
        return False
    
    def _calculate_distance(self, signal1: RFSignal, signal2: RFSignal) -> float:
        """Calculate distance between two signals (placeholder)."""
        if not signal1.location or not signal2.location:
            return 0
        return np.sqrt(
            (signal1.location[0] - signal2.location[0])**2 + 
            (signal1.location[1] - signal2.location[1])**2
        )


class HandoffDetector:
    """Detects signal handoffs and relay patterns."""
    
    def __init__(self, handoff_threshold: float = 0.7):
        self.handoff_threshold = handoff_threshold
        self.signal_history = defaultdict(list)
    
    def detect_handoffs(self, signals: List[RFSignal]) -> List[Dict]:
        """Identify signal handoff sequences."""
        handoffs = []
        
        # Track RSSI changes over time for same device
        for signal in signals:
            self.signal_history[signal.mac_address].append(signal)
        
        # Analyze each device's RSSI pattern
        for mac, history in self.signal_history.items():
            if len(history) < 3:
                continue
            
            # Sort by timestamp
            history.sort(key=lambda x: x.timestamp)
            
            # Detect RSSI drop-off and pickup patterns
            handoff_events = self._find_handoff_events(history)
            handoffs.extend(handoff_events)
        
        return handoffs
    
    def _find_handoff_events(self, signal_history: List[RFSignal]) -> List[Dict]:
        """Find individual handoff events in signal history."""
        events = []
        rssi_values = [s.rssi for s in signal_history]
        
        for i in range(1, len(rssi_values) - 1):
            prev_rssi = rssi_values[i-1]
            curr_rssi = rssi_values[i]
            next_rssi = rssi_values[i+1]
            
            # Detect valley pattern (drop then recovery)
            if prev_rssi > curr_rssi and next_rssi > curr_rssi:
                if (prev_rssi - curr_rssi) > 10 and (next_rssi - curr_rssi) > 10:
                    events.append({
                        'timestamp': signal_history[i].timestamp,
                        'device': signal_history[i].mac_address,
                        'pattern': 'handoff_valley',
                        'rssi_drop': prev_rssi - curr_rssi,
                    })
        
        return events
    
    def detect_relay_chains(self, signals: List[RFSignal]) -> List[Dict]:
        """Identify multi-hop relay patterns suggesting surveillance network."""
        relay_chains = []
        device_connections = defaultdict(set)
        
        # Build connectivity graph
        for signal in signals:
            # Look for nearby devices that could relay
            for other_signal in signals:
                if (signal.mac_address != other_signal.mac_address and 
                    abs((signal.timestamp - other_signal.timestamp).total_seconds()) < 5):
                    device_connections[signal.mac_address].add(other_signal.mac_address)
        
        # Find chains of 3+ connected devices
        for device, connections in device_connections.items():
            if len(connections) >= 2:
                relay_chains.append({
                    'root_device': device,
                    'relay_count': len(connections),
                    'connected_devices': list(connections),
                    'threat_level': 'medium' if len(connections) >= 3 else 'low',
                })
        
        return relay_chains
