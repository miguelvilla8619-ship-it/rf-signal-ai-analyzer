import numpy as np
from typing import List, Dict, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import logging
import re

logger = logging.getLogger(__name__)

class HiddenDeviceScanner:
    """Detects hidden cameras, covert WiFi, and stealth Bluetooth devices."""
    
    # Hidden camera signatures and patterns
    HIDDEN_CAMERA_INDICATORS = {
        'video_streaming': {
            'port_range': [5000, 5100, 8000, 8080, 8888, 9000, 9999],
            'protocols': ['RTSP', 'MJPEG', 'H.264', 'H.265'],
            'data_patterns': b'\xff\xd8\xff',  # JPEG SOI marker
            'bandwidth_threshold': 5000000,  # 5Mbps+ = likely video
        },
        'hidden_ssid': {
            'beacon_frame_analysis': True,
            'probe_response_empty': True,  # No SSID in beacon
            'hidden_identifier': '\\x00',
        },
        'covert_http': {
            'ports': [80, 8000, 8080, 8888, 9000],
            'suspicious_user_agents': [
                'DVR', 'Camera', 'IP-Camera', 'Webcam', 'Surveillance',
                'Motion', 'Mjpg', 'EasyIP'
            ],
        },
        'onvif_protocol': {
            'port': 8080,
            'services': ['ptz', 'media', 'device'],
            'namespace': 'http://www.onvif.org',
        },
    }
    
    # Stealth Bluetooth device signatures
    STEALTH_BLUETOOTH_SIGNATURES = {
        'hidden_mac': {
            'pattern': r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$',
            'suspicious_prefixes': ['52:54', '9A:DE', 'DA:A1'],  # Common spoofed ranges
        },
        'minimal_advertisement': {
            'empty_name': True,
            'minimal_data': True,  # <5 bytes advertisement data
            'no_manufacturer_data': True,
        },
        'persistent_device': {
            'same_mac_duration': 3600,  # Stationary for 1+ hour
            'no_movement': True,
            'unusual_activity': True,
        },
        'covert_audio': {
            'device_names': [
                'mic', 'recorder', 'audio', 'monitor',
                'listen', 'spy', 'track', 'hidden'
            ],
            'beacon_interval': 320,  # ms - slower = less obvious
        },
    }
    
    # Covert WiFi patterns
    COVERT_WIFI_PATTERNS = {
        'rogue_ap': {
            'similar_ssid': True,  # Typosquatting ("Starbuks" instead of "Starbucks")
            'same_frequency': True,  # Same channel as legitimate AP
            'signal_strength_match': True,
        },
        'hidden_broadcast': {
            'probe_response_only': True,  # Doesn't send beacon frames
            'selective_response': True,  # Only responds to specific probes
        },
        'zero_configuration': {
            'ad_hoc_mode': True,
            'no_router': True,
            'device_to_device': True,
        },
        'beacon_jamming': {
            'rapid_beacons': True,  # 10+ beacons/sec = jamming
            'channel_overlap': True,
        },
    }
    
    def __init__(self):
        self.hidden_devices = {}
        self.covert_aps = {}
        self.stealth_ble = {}
        self.suspicious_activity_log = []
    
    def scan_hidden_cameras(self, network_traffic: List[Dict], 
                           wifi_signals: List[Dict]) -> List[Dict]:
        """Comprehensive hidden camera detection across network and RF."""
        hidden_cameras = []
        
        # Detect video streaming signatures
        video_streams = self._detect_video_streams(network_traffic)
        hidden_cameras.extend(video_streams)
        
        # Detect covert HTTP camera interfaces
        http_cameras = self._detect_http_cameras(network_traffic)
        hidden_cameras.extend(http_cameras)
        
        # Detect ONVIF-based cameras (industry standard)
        onvif_cameras = self._detect_onvif_cameras(network_traffic)
        hidden_cameras.extend(onvif_cameras)
        
        # Detect hidden WiFi networks hosting cameras
        hidden_wifi_cameras = self._detect_hidden_camera_networks(wifi_signals)
        hidden_cameras.extend(hidden_wifi_cameras)
        
        # Cross-reference with known camera manufacturers
        for camera in hidden_cameras:
            camera['threat_level'] = 'critical'
            camera['type'] = 'hidden_camera'
        
        return hidden_cameras
    
    def _detect_video_streams(self, traffic: List[Dict]) -> List[Dict]:
        """Identify video streaming patterns."""
        cameras = []
        
        for packet in traffic:
            # Check for JPEG/H.264/MJPEG markers
            if packet.get('payload'):
                payload = packet['payload']
                
                # JPEG Start of Image marker
                if b'\xff\xd8\xff' in payload:
                    cameras.append({
                        'detection_type': 'jpeg_stream',
                        'source_ip': packet.get('source_ip'),
                        'destination_ip': packet.get('dest_ip'),
                        'port': packet.get('dest_port'),
                        'protocol': 'MJPEG',
                        'bandwidth_mbps': packet.get('bandwidth', 0),
                        'confidence': 0.95,
                    })
                
                # H.264 NAL unit markers
                if b'\x00\x00\x00\x01' in payload:  # H.264 start code
                    cameras.append({
                        'detection_type': 'h264_stream',
                        'source_ip': packet.get('source_ip'),
                        'destination_ip': packet.get('dest_ip'),
                        'port': packet.get('dest_port'),
                        'protocol': 'H.264',
                        'bandwidth_mbps': packet.get('bandwidth', 0),
                        'confidence': 0.92,
                    })
                
                # RTSP protocol markers
                if b'RTSP' in payload or b'rtsp://' in payload:
                    cameras.append({
                        'detection_type': 'rtsp_stream',
                        'source_ip': packet.get('source_ip'),
                        'destination_ip': packet.get('dest_ip'),
                        'port': packet.get('dest_port'),
                        'protocol': 'RTSP',
                        'confidence': 0.90,
                    })
        
        return cameras
    
    def _detect_http_cameras(self, traffic: List[Dict]) -> List[Dict]:
        """Detect covert HTTP-based camera interfaces."""
        cameras = []
        
        for packet in traffic:
            # Check HTTP User-Agent strings
            if packet.get('protocol') == 'HTTP':
                user_agent = packet.get('user_agent', '').lower()
                
                for suspicious_agent in self.HIDDEN_CAMERA_INDICATORS['covert_http']['suspicious_user_agents']:
                    if suspicious_agent.lower() in user_agent:
                        cameras.append({
                            'detection_type': 'http_camera_interface',
                            'source_ip': packet.get('source_ip'),
                            'destination_ip': packet.get('dest_ip'),
                            'port': packet.get('dest_port'),
                            'device_signature': suspicious_agent,
                            'user_agent': user_agent,
                            'confidence': 0.85,
                        })
                        break
                
                # Check for common camera paths
                uri = packet.get('uri', '').lower()
                camera_paths = [
                    '/live', '/mjpeg', '/video', '/stream', '/cam',
                    '/camera', '/snapshot', '/capture', '/view'
                ]
                for path in camera_paths:
                    if path in uri:
                        cameras.append({
                            'detection_type': 'camera_interface_path',
                            'source_ip': packet.get('source_ip'),
                            'destination_ip': packet.get('dest_ip'),
                            'port': packet.get('dest_port'),
                            'uri': uri,
                            'confidence': 0.80,
                        })
                        break
        
        return cameras
    
    def _detect_onvif_cameras(self, traffic: List[Dict]) -> List[Dict]:
        """Detect ONVIF protocol-based cameras (industry standard)."""
        cameras = []
        
        for packet in traffic:
            if packet.get('port') == 8080 or packet.get('dest_port') == 8080:
                payload = packet.get('payload', b'')
                
                # ONVIF uses SOAP/XML
                if b'onvif.org' in payload or b'ONVIF' in payload:
                    cameras.append({
                        'detection_type': 'onvif_camera',
                        'source_ip': packet.get('source_ip'),
                        'port': 8080,
                        'protocol': 'ONVIF',
                        'services': ['PTZ', 'Media', 'Imaging', 'Device'],
                        'confidence': 0.98,
                    })
        
        return cameras
    
    def _detect_hidden_camera_networks(self, wifi_signals: List[Dict]) -> List[Dict]:
        """Identify hidden WiFi networks hosting cameras."""
        cameras = []
        
        for signal in wifi_signals:
            # Hidden SSID detected
            if signal.get('hidden_ssid'):
                # Check for camera-specific data patterns
                if self._has_camera_fingerprint(signal):
                    cameras.append({
                        'detection_type': 'hidden_camera_network',
                        'bssid': signal.get('bssid'),
                        'ssid': '[HIDDEN]',
                        'channel': signal.get('channel'),
                        'signal_strength': signal.get('rssi'),
                        'encryption': signal.get('encryption'),
                        'camera_indicators': self._get_camera_indicators(signal),
                        'confidence': 0.88,
                    })
        
        return cameras
    
    def _has_camera_fingerprint(self, signal: Dict) -> bool:
        """Check if hidden network has camera characteristics."""
        # Check manufacturer OUI (Organizational Unique Identifier)
        bssid = signal.get('bssid', '')
        camera_manufacturers = [
            '00:0E:8E',  # Axis
            '00:13:95',  # Hikvision
            '00:1A:98',  # Vivotek
            '00:21:86',  # Bosch
            '00:30:F1',  # Cisco
            '00:40:96',  # Panasonic
            '00:60:E4',  # D-Link
            '00:80:F0',  # Trendnet
            '00:A0:56',  # Kingston
        ]
        
        for manufacturer in camera_manufacturers:
            if bssid.upper().startswith(manufacturer):
                return True
        
        return False
    
    def _get_camera_indicators(self, signal: Dict) -> List[str]:
        """Get camera-specific indicators from network."""
        indicators = []
        
        if signal.get('hidden_ssid'):
            indicators.append('hidden_network')
        if signal.get('no_wps'):
            indicators.append('wps_disabled')
        if signal.get('low_txpower'):
            indicators.append('low_transmission_power')
        
        return indicators
    
    def scan_stealth_bluetooth(self, ble_signals: List[Dict]) -> List[Dict]:
        """Detect hidden Bluetooth devices with covert characteristics."""
        stealth_devices = []
        
        # Detect minimal advertisement devices
        minimal_devices = self._detect_minimal_advertisements(ble_signals)
        stealth_devices.extend(minimal_devices)
        
        # Detect hidden MAC addresses
        hidden_macs = self._detect_hidden_mac_addresses(ble_signals)
        stealth_devices.extend(hidden_macs)
        
        # Detect stationary covert devices
        stationary = self._detect_stationary_devices(ble_signals)
        stealth_devices.extend(stationary)
        
        # Detect covert audio devices
        audio_devices = self._detect_covert_audio_devices(ble_signals)
        stealth_devices.extend(audio_devices)
        
        for device in stealth_devices:
            device['threat_level'] = 'high'
            device['type'] = 'hidden_bluetooth'
        
        return stealth_devices
    
    def _detect_minimal_advertisements(self, signals: List[Dict]) -> List[Dict]:
        """Identify Bluetooth devices with minimal/no name."""
        devices = []
        
        for signal in signals:
            device_name = signal.get('device_name', '')
            ad_data_length = len(signal.get('advertisement_data', b''))
            
            # Device with no name and minimal data
            if not device_name and ad_data_length < 5:
                devices.append({
                    'detection_type': 'minimal_ble_device',
                    'mac_address': signal.get('mac_address'),
                    'rssi': signal.get('rssi'),
                    'tx_power': signal.get('tx_power'),
                    'advertisement_data_length': ad_data_length,
                    'manufacturer_data': signal.get('manufacturer_data'),
                    'confidence': 0.75,
                    'indicators': ['no_device_name', 'minimal_advertisement_data'],
                })
        
        return devices
    
    def _detect_hidden_mac_addresses(self, signals: List[Dict]) -> List[Dict]:
        """Identify suspicious MAC addresses (likely spoofed)."""
        devices = []
        mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$')
        
        for signal in signals:
            mac = signal.get('mac_address', '')
            
            if mac_pattern.match(mac):
                # Check for suspicious MAC ranges
                mac_prefix = mac[:8].upper()
                
                for suspicious_prefix in self.STEALTH_BLUETOOTH_SIGNATURES['hidden_mac']['suspicious_prefixes']:
                    if mac_prefix == suspicious_prefix:
                        devices.append({
                            'detection_type': 'spoofed_mac_address',
                            'mac_address': mac,
                            'manufacturer_prefix': mac_prefix,
                            'rssi': signal.get('rssi'),
                            'device_name': signal.get('device_name'),
                            'confidence': 0.85,
                            'indicators': ['suspicious_mac_prefix', 'likely_spoofed'],
                        })
        
        return devices
    
    def _detect_stationary_devices(self, signals: List[Dict]) -> List[Dict]:
        """Identify Bluetooth devices that remain stationary (hidden cameras)."""
        devices = []
        stationary_threshold = 3600  # 1 hour
        rssi_variance_threshold = 3  # dBm
        
        # Group signals by MAC address
        mac_groups = defaultdict(list)
        for signal in signals:
            mac_groups[signal.get('mac_address')].append(signal)
        
        # Analyze each MAC group
        for mac, signal_group in mac_groups.items():
            if len(signal_group) < 10:  # Need multiple detections
                continue
            
            # Check if RSSI is stable (no movement)
            rssi_values = [s.get('rssi', -100) for s in signal_group]
            rssi_std = np.std(rssi_values)
            
            # Check time span
            timestamps = sorted([s.get('timestamp') for s in signal_group])
            if timestamps:
                time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                
                if time_span > stationary_threshold and rssi_std < rssi_variance_threshold:
                    devices.append({
                        'detection_type': 'stationary_hidden_device',
                        'mac_address': mac,
                        'rssi_average': np.mean(rssi_values),
                        'rssi_variance': rssi_std,
                        'observation_duration_hours': time_span / 3600,
                        'detection_count': len(signal_group),
                        'device_name': signal_group[0].get('device_name'),
                        'confidence': 0.90,
                        'indicators': ['stationary_signal', 'no_movement', 'long_duration'],
                    })
        
        return devices
    
    def _detect_covert_audio_devices(self, signals: List[Dict]) -> List[Dict]:
        """Identify hidden audio recorders and microphones."""
        devices = []
        
        for signal in signals:
            device_name = signal.get('device_name', '').lower()
            beacon_interval = signal.get('beacon_interval', 100)
            
            # Check for audio-related device names
            audio_keywords = [
                'mic', 'microphone', 'recorder', 'audio', 'monitor',
                'listen', 'spy', 'track', 'hidden', 'voice', 'record'
            ]
            
            name_match = any(keyword in device_name for keyword in audio_keywords)
            
            # Check for suspicious beacon interval (slower = less obvious)
            is_slow_beacon = beacon_interval > 200  # ms
            
            if name_match or (is_slow_beacon and len(device_name) < 5):
                devices.append({
                    'detection_type': 'covert_audio_device',
                    'mac_address': signal.get('mac_address'),
                    'device_name': device_name,
                    'beacon_interval': beacon_interval,
                    'rssi': signal.get('rssi'),
                    'confidence': 0.80,
                    'indicators': ['audio_device_name' if name_match else 'suspicious_beacon_interval'],
                })
        
        return devices
    
    def scan_covert_wifi(self, wifi_signals: List[Dict], 
                        known_networks: List[str]) -> List[Dict]:
        """Detect covert and rogue WiFi networks."""
        covert_networks = []
        
        # Detect rogue access points
        rogue_aps = self._detect_rogue_aps(wifi_signals, known_networks)
        covert_networks.extend(rogue_aps)
        
        # Detect hidden broadcasts
        hidden = self._detect_hidden_broadcasts(wifi_signals)
        covert_networks.extend(hidden)
        
        # Detect zero-configuration networks
        ad_hoc = self._detect_ad_hoc_networks(wifi_signals)
        covert_networks.extend(ad_hoc)
        
        # Detect beacon jamming
        jamming = self._detect_beacon_jamming(wifi_signals)
        covert_networks.extend(jamming)
        
        for network in covert_networks:
            network['threat_level'] = 'high'
            network['type'] = 'covert_wifi'
        
        return covert_networks
    
    def _detect_rogue_aps(self, signals: List[Dict], 
                         known_networks: List[str]) -> List[Dict]:
        """Identify rogue access points with spoofed SSIDs."""
        rogue = []
        
        for signal in signals:
            ssid = signal.get('ssid', '')
            
            # Check for typosquatting (similar to legitimate networks)
            for known_ssid in known_networks:
                if self._is_similar_ssid(ssid, known_ssid):
                    rogue.append({
                        'detection_type': 'rogue_access_point',
                        'ssid': ssid,
                        'bssid': signal.get('bssid'),
                        'channel': signal.get('channel'),
                        'rssi': signal.get('rssi'),
                        'encryption': signal.get('encryption'),
                        'legitimate_ssid': known_ssid,
                        'spoofing_method': 'typosquatting',
                        'confidence': 0.87,
                    })
        
        return rogue
    
    def _is_similar_ssid(self, ssid1: str, ssid2: str) -> bool:
        """Check if two SSIDs are similar (typosquatting detection)."""
        # Levenshtein distance
        s1, s2 = ssid1.lower(), ssid2.lower()
        
        if len(s1) < 3 or len(s2) < 3:
            return s1 == s2
        
        # Calculate similarity
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        similarity = matches / max(len(s1), len(s2))
        
        return 0.7 < similarity < 0.99  # Similar but not identical
    
    def _detect_hidden_broadcasts(self, signals: List[Dict]) -> List[Dict]:
        """Identify networks that don't broadcast SSIDs."""
        hidden = []
        
        for signal in signals:
            if signal.get('hidden_ssid'):
                hidden.append({
                    'detection_type': 'hidden_broadcast_network',
                    'ssid': '[HIDDEN]',
                    'bssid': signal.get('bssid'),
                    'channel': signal.get('channel'),
                    'rssi': signal.get('rssi'),
                    'encryption': signal.get('encryption'),
                    'beacon_type': signal.get('beacon_type'),
                    'confidence': 0.80,
                })
        
        return hidden
    
    def _detect_ad_hoc_networks(self, signals: List[Dict]) -> List[Dict]:
        """Identify ad-hoc (device-to-device) networks."""
        ad_hoc = []
        
        for signal in signals:
            if signal.get('network_type') == 'ad_hoc' or signal.get('infrastructure_mode') == False:
                ad_hoc.append({
                    'detection_type': 'ad_hoc_network',
                    'ssid': signal.get('ssid'),
                    'bssid': signal.get('bssid'),
                    'channel': signal.get('channel'),
                    'rssi': signal.get('rssi'),
                    'network_mode': 'ad_hoc',
                    'confidence': 0.85,
                    'indicators': ['no_router', 'device_to_device', 'potentially_suspicious'],
                })
        
        return ad_hoc
    
    def _detect_beacon_jamming(self, signals: List[Dict]) -> List[Dict]:
        """Identify beacon jamming patterns."""
        jamming = []
        
        for signal in signals:
            beacon_rate = signal.get('beacon_rate', 0)  # beacons per second
            
            # Normal beacon rate is 1-10 per second; >10 = jamming
            if beacon_rate > 10:
                jamming.append({
                    'detection_type': 'beacon_jamming',
                    'bssid': signal.get('bssid'),
                    'ssid': signal.get('ssid'),
                    'beacon_rate_per_sec': beacon_rate,
                    'channel': signal.get('channel'),
                    'rssi': signal.get('rssi'),
                    'confidence': 0.90,
                    'indicators': ['excessive_beacon_transmission', 'channel_flooding'],
                })
        
        return jamming
    
    def generate_threat_report(self, hidden_cameras: List[Dict],
                              stealth_ble: List[Dict],
                              covert_wifi: List[Dict]) -> Dict:
        """Generate comprehensive hidden device threat report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_threats': len(hidden_cameras) + len(stealth_ble) + len(covert_wifi),
                'hidden_cameras': len(hidden_cameras),
                'stealth_bluetooth': len(stealth_ble),
                'covert_wifi': len(covert_wifi),
            },
            'threats': {
                'cameras': hidden_cameras,
                'bluetooth': stealth_ble,
                'wifi': covert_wifi,
            },
            'risk_level': self._assess_overall_risk(hidden_cameras, stealth_ble, covert_wifi),
            'recommendations': self._generate_recommendations(hidden_cameras, stealth_ble, covert_wifi),
        }
        
        return report
    
    def _assess_overall_risk(self, cameras: List[Dict], 
                            ble: List[Dict],
                            wifi: List[Dict]) -> str:
        """Assess overall security risk level."""
        threat_count = len(cameras) + len(ble) + len(wifi)
        critical_count = sum(1 for t in cameras + ble + wifi if t.get('threat_level') == 'critical')
        
        if critical_count > 0:
            return 'CRITICAL'
        elif threat_count > 5:
            return 'HIGH'
        elif threat_count > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendations(self, cameras: List[Dict],
                                 ble: List[Dict],
                                 wifi: List[Dict]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if cameras:
            recommendations.append(
                f"⚠️ CRITICAL: {len(cameras)} hidden camera(s) detected. "
                "Scan location thoroughly for suspicious devices."
            )
        
        if ble:
            recommendations.append(
                f"⚠️ HIGH: {len(ble)} stealth Bluetooth device(s) detected. "
                "Check for unauthorized tracking/recording devices."
            )
        
        if wifi:
            recommendations.append(
                f"⚠️ HIGH: {len(wifi)} covert WiFi network(s) detected. "
                "Avoid connecting and report to network administrator."
            )
        
        if not (cameras or ble or wifi):
            recommendations.append("✓ No hidden devices detected in this scan.")
        
        recommendations.append("• Update device firmware regularly")
        recommendations.append("• Enable MAC address randomization")
        recommendations.append("• Use VPN on public networks")
        recommendations.append("• Disable Bluetooth/WiFi when not in use")
        recommendations.append("• Perform periodic security scans")
        
        return recommendations
