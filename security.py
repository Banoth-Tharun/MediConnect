"""
Advanced Security & Risk Scoring Module
Handles fingerprint validation, behavioral analysis, and risk calculation
"""

import sqlite3
import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Tuple, Optional, List
from functools import lru_cache


class PredictiveRiskAnalyzer:
    """
    Analyze historical fingerprints and login attempts to predict risk scores
    Uses pattern recognition without requiring ML libraries
    """
    
    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.db.row_factory = sqlite3.Row
    
    def analyze_fingerprint_pattern(self, user_id: int, fingerprint: str, 
                                   ip_address: str) -> Dict:
        """
        Analyze fingerprint history and patterns
        Returns prediction factors for risk scoring
        """
        cursor = self.db.cursor()
        
        # Get all previous logins for this user
        cursor.execute("""
            SELECT fingerprint, ip_address, success, risk_score, timestamp
            FROM login_attempts
            WHERE user_id = ?
            ORDER BY timestamp DESC
            LIMIT 50
        """, (user_id,))
        
        history = [dict(row) for row in cursor.fetchall()]
        
        analysis = {
            'fingerprint_frequency': self._analyze_fingerprint_frequency(fingerprint, history),
            'ip_pattern': self._analyze_ip_pattern(ip_address, history),
            'success_rate': self._calculate_success_rate(history),
            'device_reliability': self._calculate_device_reliability(fingerprint, history),
            'ip_reliability': self._calculate_ip_reliability(ip_address, history),
            'anomaly_score': self._detect_anomalies(fingerprint, ip_address, history),
            'trusted_combination': self._check_trusted_combination(fingerprint, ip_address, history)
        }
        
        return analysis
    
    def _analyze_fingerprint_frequency(self, fingerprint: str, history: List[Dict]) -> Dict:
        """
        Analyze how often this fingerprint appears in history
        More frequent = more trusted
        """
        if not history:
            return {'status': 'new_fingerprint', 'frequency': 0, 'prediction': 'high_risk'}
        
        fp_count = sum(1 for h in history if h['fingerprint'] == fingerprint)
        total_logins = len(history)
        frequency = fp_count / total_logins if total_logins > 0 else 0
        
        if frequency >= 0.8:  # Used in 80%+ of logins
            return {'status': 'primary_device', 'frequency': frequency, 'prediction': 'low_risk'}
        elif frequency >= 0.5:  # Used in 50%+ of logins
            return {'status': 'regular_device', 'frequency': frequency, 'prediction': 'medium_risk'}
        elif frequency > 0:  # Used occasionally
            return {'status': 'occasional_device', 'frequency': frequency, 'prediction': 'medium_risk'}
        else:  # Never seen before
            return {'status': 'new_device', 'frequency': 0, 'prediction': 'high_risk'}
    
    def _analyze_ip_pattern(self, ip_address: str, history: List[Dict]) -> Dict:
        """
        Analyze IP address usage patterns
        Regular IPs = trusted, frequent changes = suspicious
        """
        if not history:
            return {'status': 'new_ip', 'frequency': 0, 'prediction': 'high_risk'}
        
        ip_count = sum(1 for h in history if h['ip_address'] == ip_address)
        total_logins = len(history)
        frequency = ip_count / total_logins if total_logins > 0 else 0
        
        # Get unique IPs in last 30 days
        thirty_days_ago = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        recent_ips = set()
        for h in history:
            if h['timestamp'] > thirty_days_ago:
                recent_ips.add(h['ip_address'])
        
        if frequency >= 0.7:  # Used in 70%+ of logins
            return {
                'status': 'primary_ip',
                'frequency': frequency,
                'unique_ips_30d': len(recent_ips),
                'prediction': 'low_risk'
            }
        elif len(recent_ips) > 10:  # More than 10 IPs in 30 days
            return {
                'status': 'ip_hopper',
                'frequency': frequency,
                'unique_ips_30d': len(recent_ips),
                'prediction': 'high_risk'
            }
        elif frequency > 0:
            return {
                'status': 'known_ip',
                'frequency': frequency,
                'unique_ips_30d': len(recent_ips),
                'prediction': 'medium_risk'
            }
        else:
            return {
                'status': 'new_ip',
                'frequency': 0,
                'unique_ips_30d': len(recent_ips),
                'prediction': 'high_risk'
            }
    
    def _calculate_success_rate(self, history: List[Dict]) -> Dict:
        """
        Calculate login success rate
        High success = trustworthy account
        """
        if not history:
            return {'success_rate': 0, 'total_attempts': 0, 'prediction': 'unknown'}
        
        successes = sum(1 for h in history if h['success'] == 1)
        total = len(history)
        rate = successes / total if total > 0 else 0
        
        if rate >= 0.95:  # 95%+ success
            return {'success_rate': rate, 'total_attempts': total, 'prediction': 'low_risk'}
        elif rate >= 0.80:  # 80%+ success
            return {'success_rate': rate, 'total_attempts': total, 'prediction': 'medium_risk'}
        elif rate >= 0.50:  # 50%+ success
            return {'success_rate': rate, 'total_attempts': total, 'prediction': 'high_risk'}
        else:  # Low success rate
            return {'success_rate': rate, 'total_attempts': total, 'prediction': 'very_high_risk'}
    
    def _calculate_device_reliability(self, fingerprint: str, history: List[Dict]) -> Dict:
        """
        Calculate how reliable a device is based on past logins
        """
        device_attempts = [h for h in history if h['fingerprint'] == fingerprint]
        
        if not device_attempts:
            return {'reliability': 0, 'attempts': 0, 'avg_risk': 0, 'prediction': 'unknown'}
        
        successes = sum(1 for h in device_attempts if h['success'] == 1)
        rate = successes / len(device_attempts)
        avg_risk = sum(h['risk_score'] for h in device_attempts) / len(device_attempts)
        
        if rate >= 0.90 and avg_risk < 30:  # Reliable and low-risk
            return {
                'reliability': rate,
                'attempts': len(device_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'very_low_risk'
            }
        elif rate >= 0.70 and avg_risk < 50:
            return {
                'reliability': rate,
                'attempts': len(device_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'low_risk'
            }
        elif avg_risk > 70:  # High-risk device
            return {
                'reliability': rate,
                'attempts': len(device_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'high_risk'
            }
        else:
            return {
                'reliability': rate,
                'attempts': len(device_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'medium_risk'
            }
    
    def _calculate_ip_reliability(self, ip_address: str, history: List[Dict]) -> Dict:
        """
        Calculate how reliable an IP address is based on past logins
        """
        ip_attempts = [h for h in history if h['ip_address'] == ip_address]
        
        if not ip_attempts:
            return {'reliability': 0, 'attempts': 0, 'avg_risk': 0, 'prediction': 'unknown'}
        
        successes = sum(1 for h in ip_attempts if h['success'] == 1)
        rate = successes / len(ip_attempts)
        avg_risk = sum(h['risk_score'] for h in ip_attempts) / len(ip_attempts)
        
        if rate >= 0.90 and avg_risk < 30:
            return {
                'reliability': rate,
                'attempts': len(ip_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'very_low_risk'
            }
        elif avg_risk > 60:
            return {
                'reliability': rate,
                'attempts': len(ip_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'high_risk'
            }
        else:
            return {
                'reliability': rate,
                'attempts': len(ip_attempts),
                'avg_risk': round(avg_risk, 2),
                'prediction': 'medium_risk'
            }
    
    def _detect_anomalies(self, fingerprint: str, ip_address: str, history: List[Dict]) -> Dict:
        """
        Detect anomalies in login patterns
        """
        if not history:
            return {'anomalies': [], 'anomaly_score': 0, 'prediction': 'unknown'}
        
        anomalies = []
        anomaly_score = 0
        
        # Check for new device + new IP combination
        combo_exists = any(
            h['fingerprint'] == fingerprint and h['ip_address'] == ip_address 
            for h in history
        )
        if not combo_exists:
            anomalies.append('new_device_ip_combination')
            anomaly_score += 20
        
        # Check for rapid IP changes
        if len(history) >= 3:
            recent_ips = [h['ip_address'] for h in history[:3]]
            if len(set(recent_ips)) == 3:  # 3 different IPs in last 3 logins
                anomalies.append('rapid_ip_changes')
                anomaly_score += 25
        
        # Check for multiple devices in short time
        if len(history) >= 5:
            recent_fps = [h['fingerprint'] for h in history[:5]]
            if len(set(recent_fps)) >= 4:  # 4+ devices in last 5 logins
                anomalies.append('multiple_devices_short_time')
                anomaly_score += 20
        
        # Check for unusual login time
        current_hour = datetime.now(timezone.utc).hour
        if history:
            typical_hours = set(
                datetime.fromisoformat(h['timestamp']).hour 
                for h in history[:10]
            )
            if current_hour not in typical_hours and len(typical_hours) >= 3:
                anomalies.append('unusual_login_hour')
                anomaly_score += 15
        
        # Normalize score
        anomaly_score = min(100, anomaly_score)
        
        if anomaly_score > 60:
            prediction = 'high_risk'
        elif anomaly_score > 30:
            prediction = 'medium_risk'
        else:
            prediction = 'low_risk'
        
        return {
            'anomalies': anomalies,
            'anomaly_score': anomaly_score,
            'prediction': prediction
        }
    
    def _check_trusted_combination(self, fingerprint: str, ip_address: str, 
                                   history: List[Dict]) -> Dict:
        """
        Check if this fingerprint+IP combination has successful logins
        """
        combo_logins = [
            h for h in history 
            if h['fingerprint'] == fingerprint and h['ip_address'] == ip_address
        ]
        
        if not combo_logins:
            return {
                'combo_seen_before': False,
                'combo_successes': 0,
                'prediction': 'unknown'
            }
        
        successes = sum(1 for h in combo_logins if h['success'] == 1)
        total = len(combo_logins)
        
        if successes >= total * 0.9:  # 90%+ success with this combo
            return {
                'combo_seen_before': True,
                'combo_attempts': total,
                'combo_successes': successes,
                'combo_reliability': successes / total,
                'prediction': 'low_risk'
            }
        else:
            return {
                'combo_seen_before': True,
                'combo_attempts': total,
                'combo_successes': successes,
                'combo_reliability': successes / total,
                'prediction': 'medium_risk'
            }
    
    def predict_risk_adjustment(self, analysis: Dict) -> float:
        """
        Predict a risk score adjustment based on historical analysis
        Returns a value -30 to +30 to adjust base risk score
        """
        adjustments = []
        
        # Fingerprint pattern
        fp_pred = analysis.get('fingerprint_frequency', {}).get('prediction', 'medium_risk')
        if fp_pred == 'low_risk':
            adjustments.append(-15)
        elif fp_pred == 'high_risk':
            adjustments.append(+15)
        
        # IP pattern
        ip_pred = analysis.get('ip_pattern', {}).get('prediction', 'medium_risk')
        if ip_pred == 'low_risk':
            adjustments.append(-12)
        elif ip_pred == 'high_risk' or ip_pred == 'ip_hopper':
            adjustments.append(+18)
        
        # Success rate
        success_pred = analysis.get('success_rate', {}).get('prediction', 'unknown')
        if success_pred == 'low_risk':
            adjustments.append(-10)
        elif success_pred == 'very_high_risk':
            adjustments.append(+20)
        
        # Device reliability
        device_pred = analysis.get('device_reliability', {}).get('prediction', 'unknown')
        if device_pred == 'very_low_risk':
            adjustments.append(-12)
        elif device_pred == 'high_risk':
            adjustments.append(+15)
        
        # Anomaly score
        anomaly_score = analysis.get('anomaly_score', {}).get('anomaly_score', 0)
        adjustments.append(anomaly_score / 3)  # 0-33 points
        
        # Average adjustment
        final_adjustment = sum(adjustments) / len(adjustments) if adjustments else 0
        return round(final_adjustment, 2)


class RiskScorer:
    """
    Calculate login risk score based on multiple factors:
    - Fingerprint matching
    - IP address changes
    - Behavioral patterns
    - Time-based anomalies
    - Device unknown status
    """
    
    # Risk thresholds
    RISK_LEVELS = {
        'low': (0, 30),          # 0-30: Allow
        'medium': (30, 60),      # 30-60: Challenge (OTP)
        'high': (60, 100)        # 60-100: Block/Extra verification
    }
    
    # Risk factor weights (total = 100)
    WEIGHTS = {
        'new_fingerprint': 25,      # Unknown device
        'new_ip': 20,               # New IP address
        'impossible_travel': 25,    # Too fast movement between IPs
        'behavior_anomaly': 15,     # Time/frequency anomalies
        'concurrent_login': 10,     # Multiple simultaneous logins
        'failed_attempts': 5        # Recent failed attempts
    }
    
    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.db.row_factory = sqlite3.Row
    
    def calculate_risk(self, user_id: Optional[int], username: str, 
                      fingerprint: str, ip_address: str, 
                      browser: str, os: str) -> Dict:
        """
        Main risk calculation function with predictive analysis
        Returns dict with risk_score, level, factors, prediction, and recommendation
        """
        
        risk_score = 0
        risk_factors = {}
        predictive_data = {}
        
        if user_id:
            # Check fingerprint match
            fp_risk, fp_details = self._check_fingerprint(user_id, fingerprint)
            risk_score += fp_risk * (self.WEIGHTS['new_fingerprint'] / 100)
            risk_factors['fingerprint'] = fp_details
            
            # Check IP address
            ip_risk, ip_details = self._check_ip_address(user_id, ip_address)
            risk_score += ip_risk * (self.WEIGHTS['new_ip'] / 100)
            risk_factors['ip_address'] = ip_details
            
            # Check impossible travel
            travel_risk, travel_details = self._check_impossible_travel(user_id, ip_address)
            risk_score += travel_risk * (self.WEIGHTS['impossible_travel'] / 100)
            risk_factors['impossible_travel'] = travel_details
            
            # Check behavioral anomalies
            behavior_risk, behavior_details = self._check_behavior_anomaly(user_id)
            risk_score += behavior_risk * (self.WEIGHTS['behavior_anomaly'] / 100)
            risk_factors['behavior_anomaly'] = behavior_details
            
            # Check concurrent logins
            concurrent_risk, concurrent_details = self._check_concurrent_logins(user_id)
            risk_score += concurrent_risk * (self.WEIGHTS['concurrent_login'] / 100)
            risk_factors['concurrent_logins'] = concurrent_details
            
            # PREDICTIVE ANALYSIS: Analyze historical patterns
            analyzer = PredictiveRiskAnalyzer(self.db)
            pattern_analysis = analyzer.analyze_fingerprint_pattern(
                user_id, fingerprint, ip_address
            )
            risk_adjustment = analyzer.predict_risk_adjustment(pattern_analysis)
            
            # Apply prediction adjustment
            original_score = risk_score
            risk_score = min(100, max(0, risk_score + risk_adjustment))
            
            # Store predictive data
            predictive_data = {
                'fingerprint_pattern': pattern_analysis.get('fingerprint_frequency', {}),
                'ip_pattern': pattern_analysis.get('ip_pattern', {}),
                'device_reliability': pattern_analysis.get('device_reliability', {}),
                'ip_reliability': pattern_analysis.get('ip_reliability', {}),
                'anomalies': pattern_analysis.get('anomaly_score', {}),
                'trusted_combo': pattern_analysis.get('trusted_combination', {}),
                'risk_adjustment': risk_adjustment,
                'original_risk_score': round(original_score, 2),
                'adjusted_risk_score': round(risk_score, 2)
            }
            risk_factors['predictive_analysis'] = predictive_data
        
        # Check failed attempts
        failed_risk, failed_details = self._check_failed_attempts(username, ip_address)
        risk_score += failed_risk * (self.WEIGHTS['failed_attempts'] / 100)
        risk_factors['failed_attempts'] = failed_details
        
        # Normalize to 0-100
        risk_score = min(100, max(0, risk_score))
        
        # Determine risk level
        risk_level = self._get_risk_level(risk_score)
        
        # Get recommendation
        recommendation = self._get_recommendation(risk_score, risk_level)
        
        return {
            'risk_score': round(risk_score, 2),
            'risk_level': risk_level,
            'factors': risk_factors,
            'predictive_data': predictive_data,
            'recommendation': recommendation,
            'requires_challenge': risk_level in ['medium', 'high']
        }
    
    def _check_fingerprint(self, user_id: int, fingerprint: str) -> Tuple[float, Dict]:
        """
        Check if fingerprint is known and trusted
        Returns (risk_score 0-100, details_dict)
        """
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT * FROM device_fingerprints 
            WHERE user_id = ? AND fingerprint = ?
            ORDER BY last_seen DESC LIMIT 1
        """, (user_id, fingerprint))
        
        existing = cursor.fetchone()
        
        if existing:
            # Known device
            is_trusted = existing['is_trusted'] == 1
            
            if is_trusted:
                # Check if trust is still valid
                if existing['trust_expires_at']:
                    expires = datetime.fromisoformat(existing['trust_expires_at'])
                    if datetime.now(timezone.utc) > expires:
                        return (50, {
                            'status': 'trusted_expired',
                            'device': existing['device_name'] or 'Unknown',
                            'last_seen': existing['last_seen']
                        })
                    else:
                        return (0, {
                            'status': 'trusted',
                            'device': existing['device_name'] or 'Unknown',
                            'last_seen': existing['last_seen']
                        })
                else:
                    # Permanent trust
                    return (0, {
                        'status': 'trusted',
                        'device': existing['device_name'] or 'Unknown',
                        'last_seen': existing['last_seen']
                    })
            else:
                # Known but not trusted
                return (40, {
                    'status': 'known_untrusted',
                    'device': existing['device_name'] or 'Unknown',
                    'first_seen': existing['first_seen']
                })
        else:
            # Unknown device
            return (100, {'status': 'new_device'})
    
    def _check_ip_address(self, user_id: int, ip_address: str) -> Tuple[float, Dict]:
        """
        Check if IP address is known for this user
        """
        cursor = self.db.cursor()
        
        # Get last login IP
        cursor.execute("""
            SELECT ip_address FROM login_attempts 
            WHERE user_id = ? AND success = 1
            ORDER BY timestamp DESC LIMIT 1
        """, (user_id,))
        
        last_login = cursor.fetchone()
        
        if last_login:
            if last_login['ip_address'] == ip_address:
                return (0, {'status': 'known_ip', 'ip': ip_address})
            else:
                return (60, {
                    'status': 'new_ip',
                    'current': ip_address,
                    'previous': last_login['ip_address']
                })
        else:
            return (0, {'status': 'first_login', 'ip': ip_address})
    
    def _check_impossible_travel(self, user_id: int, ip_address: str) -> Tuple[float, Dict]:
        """
        Check if travel between IPs is physically possible
        (Simple check: just detect quick IP changes)
        """
        cursor = self.db.cursor()
        
        cursor.execute("""
            SELECT timestamp, ip_address FROM login_attempts 
            WHERE user_id = ? AND success = 1
            ORDER BY timestamp DESC LIMIT 1
        """, (user_id,))
        
        last_login = cursor.fetchone()
        
        if not last_login or last_login['ip_address'] == ip_address:
            return (0, {'status': 'no_travel', 'ip': ip_address})
        
        # Check time difference
        last_time = datetime.fromisoformat(last_login['timestamp'])
        time_diff = (datetime.now(timezone.utc) - last_time).total_seconds() / 3600  # hours
        
        # If less than 1 hour between logins from different IPs, it's suspicious
        if time_diff < 1:
            return (80, {
                'status': 'impossible_travel',
                'time_diff_hours': round(time_diff, 2),
                'previous_ip': last_login['ip_address'],
                'current_ip': ip_address
            })
        elif time_diff < 4:  # Less than 4 hours
            return (40, {
                'status': 'suspicious_travel',
                'time_diff_hours': round(time_diff, 2),
                'previous_ip': last_login['ip_address'],
                'current_ip': ip_address
            })
        else:
            return (0, {'status': 'normal_travel'})
    
    def _check_behavior_anomaly(self, user_id: int) -> Tuple[float, Dict]:
        """
        Check for behavioral anomalies (login time, frequency)
        """
        cursor = self.db.cursor()
        
        # Get recent successful logins
        cursor.execute("""
            SELECT timestamp FROM login_attempts 
            WHERE user_id = ? AND success = 1
            ORDER BY timestamp DESC LIMIT 10
        """, (user_id,))
        
        logins = cursor.fetchall()
        
        if len(logins) < 3:
            return (0, {'status': 'insufficient_history'})
        
        # Extract hours from login times
        login_hours = []
        for login in logins:
            dt = datetime.fromisoformat(login['timestamp'])
            login_hours.append(dt.hour)
        
        # Check if current login hour is within typical range
        current_hour = datetime.now(timezone.utc).hour
        typical_hours = set(login_hours)
        
        if current_hour not in typical_hours:
            # Unusual login time
            return (50, {
                'status': 'unusual_time',
                'current_hour': current_hour,
                'typical_hours': list(typical_hours)
            })
        
        # Check login frequency
        cursor.execute("""
            SELECT COUNT(*) as count FROM login_attempts 
            WHERE user_id = ? AND success = 1
            AND timestamp > datetime('now', '-1 day')
        """, (user_id,))
        
        daily_logins = cursor.fetchone()['count']
        
        if daily_logins > 20:  # More than 20 logins per day
            return (60, {
                'status': 'excessive_logins',
                'daily_count': daily_logins
            })
        
        return (0, {'status': 'normal_behavior'})
    
    def _check_concurrent_logins(self, user_id: int) -> Tuple[float, Dict]:
        """
        Check for concurrent logins from different locations
        """
        cursor = self.db.cursor()
        
        # Check logins in last 5 minutes
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address) as ip_count
            FROM login_attempts 
            WHERE user_id = ? 
            AND timestamp > datetime('now', '-5 minutes')
        """, (user_id,))
        
        result = cursor.fetchone()
        ip_count = result['ip_count']
        
        if ip_count > 1:
            return (70, {
                'status': 'concurrent_ips',
                'distinct_ips': ip_count,
                'timeframe': '5_minutes'
            })
        
        return (0, {'status': 'no_concurrent_logins'})
    
    def _check_failed_attempts(self, username: str, ip_address: str) -> Tuple[float, Dict]:
        """
        Check for brute force attempts
        """
        cursor = self.db.cursor()
        
        # Check failed attempts in last 30 minutes
        cursor.execute("""
            SELECT COUNT(*) as count FROM login_attempts 
            WHERE username = ? AND success = 0
            AND timestamp > datetime('now', '-30 minutes')
        """, (username,))
        
        failed_30min = cursor.fetchone()['count']
        
        if failed_30min > 5:
            return (80, {
                'status': 'excessive_failures',
                'failures_30min': failed_30min
            })
        elif failed_30min > 2:
            return (40, {
                'status': 'multiple_failures',
                'failures_30min': failed_30min
            })
        
        return (0, {'status': 'no_recent_failures'})
    
    def _get_risk_level(self, score: float) -> str:
        """Map risk score to level"""
        for level, (min_score, max_score) in self.RISK_LEVELS.items():
            if min_score <= score < max_score:
                return level
        return 'high'
    
    def _get_recommendation(self, score: float, level: str) -> str:
        """Get action recommendation"""
        if level == 'low':
            return 'allow'
        elif level == 'medium':
            return 'challenge_otp'
        else:
            return 'block'


class FingerprintManager:
    """Manage device fingerprints and trust"""
    
    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.db.row_factory = sqlite3.Row
    
    def register_fingerprint(self, user_id: int, fingerprint: str,
                            device_name: str, browser: str, os: str,
                            ip_address: str) -> int:
        """Register a new device fingerprint"""
        cursor = self.db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO device_fingerprints 
            (user_id, fingerprint, device_name, browser, os, ip_address, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, fingerprint, device_name, browser, os, ip_address, now, now))
        
        self.db.commit()
        return cursor.lastrowid
    
    def update_fingerprint_seen(self, user_id: int, fingerprint: str):
        """Update last seen time for a fingerprint"""
        cursor = self.db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            UPDATE device_fingerprints 
            SET last_seen = ?
            WHERE user_id = ? AND fingerprint = ?
        """, (now, user_id, fingerprint))
        
        self.db.commit()
    
    def trust_device(self, user_id: int, fingerprint: str, 
                     duration_days: int = 30):
        """Mark device as trusted"""
        cursor = self.db.cursor()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=duration_days)
        
        cursor.execute("""
            UPDATE device_fingerprints 
            SET is_trusted = 1, trust_expires_at = ?
            WHERE user_id = ? AND fingerprint = ?
        """, (expires.isoformat(), user_id, fingerprint))
        
        self.db.commit()
    
    def get_trusted_devices(self, user_id: int) -> List[Dict]:
        """Get list of trusted devices"""
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT * FROM device_fingerprints 
            WHERE user_id = ? AND is_trusted = 1
            ORDER BY last_seen DESC
        """, (user_id,))
        
        return [dict(row) for row in cursor.fetchall()]


class SecurityLogger:
    """Log security events and login attempts"""
    
    def __init__(self, db_connection: sqlite3.Connection):
        self.db = db_connection
        self.db.row_factory = sqlite3.Row
    
    def log_login_attempt(self, username: str, user_id: Optional[int],
                         fingerprint: str, ip_address: str,
                         browser: str, os: str, success: bool,
                         risk_score: float, risk_factors: Dict,
                         challenge_type: Optional[str] = None) -> int:
        """Log a login attempt with risk assessment"""
        cursor = self.db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO login_attempts 
            (user_id, username, fingerprint, ip_address, browser, os,
             success, risk_score, risk_factors, timestamp, challenge_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, fingerprint, ip_address, browser, os,
              1 if success else 0, risk_score, json.dumps(risk_factors),
              now, challenge_type))
        
        self.db.commit()
        return cursor.lastrowid
    
    def log_security_event(self, username: str, user_id: Optional[int],
                          event_type: str, risk_level: str,
                          ip_address: Optional[str],
                          fingerprint: Optional[str],
                          details: Dict):
        """Log a security event"""
        cursor = self.db.cursor()
        now = datetime.now(timezone.utc).isoformat()
        
        cursor.execute("""
            INSERT INTO security_logs 
            (user_id, username, event_type, risk_level, ip_address, fingerprint, details, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (user_id, username, event_type, risk_level, ip_address,
              fingerprint, json.dumps(details), now))
        
        self.db.commit()
    
    def get_security_logs(self, user_id: Optional[int] = None, 
                         limit: int = 100) -> List[Dict]:
        """Get security logs"""
        cursor = self.db.cursor()
        
        if user_id:
            cursor.execute("""
                SELECT * FROM security_logs 
                WHERE user_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (user_id, limit))
        else:
            cursor.execute("""
                SELECT * FROM security_logs 
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]


def create_jwt_token(user_id: int, username: str, fingerprint: str,
                     ip_address: str) -> str:
    """
    Create a simple JWT-like token for session validation
    In production, use proper JWT library
    """
    import base64
    
    payload = {
        'user_id': user_id,
        'username': username,
        'fingerprint': fingerprint,
        'ip_address': ip_address,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    }
    
    token = base64.b64encode(json.dumps(payload).encode()).decode()
    return token


def validate_jwt_token(token: str, fingerprint: str, ip_address: str) -> Tuple[bool, Optional[Dict]]:
    """
    Validate JWT token
    Returns (is_valid, payload_dict)
    """
    import base64
    
    try:
        decoded = base64.b64decode(token).decode()
        payload = json.loads(decoded)
        
        # Check expiration
        expires_at = datetime.fromisoformat(payload['expires_at'])
        if datetime.now(timezone.utc) > expires_at:
            return (False, None)
        
        # Validate fingerprint and IP match
        if payload['fingerprint'] != fingerprint or payload['ip_address'] != ip_address:
            return (False, None)
        
        return (True, payload)
    except Exception as e:
        return (False, None)
