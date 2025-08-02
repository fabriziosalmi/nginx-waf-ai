"""
ML Engine Module

Handles real-time machine learning for threat detection and analysis.
Thread-safe implementation with comprehensive error handling.
"""

import threading
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from typing import List, Dict, Tuple, Optional
import joblib
import json
from datetime import datetime
from dataclasses import dataclass
from loguru import logger
import os

# Import error handling utilities
from .error_handling import retry_decorator, error_recovery, degradation_manager

# No local metrics - all metrics updates handled by main.py to avoid conflicts
METRICS_AVAILABLE = True


@dataclass
class ThreatPrediction:
    """Represents a threat prediction result"""
    request_id: str
    threat_score: float
    threat_type: str
    confidence: float
    features_used: List[str]
    timestamp: datetime
    
    def to_dict(self) -> Dict:
        return {
            'request_id': self.request_id,
            'threat_score': self.threat_score,
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'features_used': self.features_used,
            'timestamp': self.timestamp.isoformat()
        }


class MLEngine:
    """Thread-safe real-time machine learning engine for threat detection"""
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.is_trained = False
        self._lock = threading.RLock()  # Reentrant lock for thread safety
        self.model_version = "1.0.0"
        self.last_training_time = None
        
    def _validate_request_data(self, request: Dict) -> bool:
        """Validate that request contains required fields with correct types"""
        required_fields = {
            'url_length': int,
            'body_length': int,
            'headers_count': int,
            'content_length': int,
            'has_suspicious_headers': bool,
            'contains_sql_patterns': bool,
            'contains_xss_patterns': bool,
            'method': str,
            'timestamp': str
        }
        
        for field, expected_type in required_fields.items():
            if field not in request:
                logger.warning(f"Missing required field: {field}")
                return False
            
            value = request[field]
            if field == 'has_suspicious_headers' or field.startswith('contains_'):
                # Accept both bool and int (0/1) for boolean fields
                if not isinstance(value, (bool, int)):
                    logger.warning(f"Invalid type for {field}: expected bool/int, got {type(value)}")
                    return False
            elif not isinstance(value, expected_type):
                logger.warning(f"Invalid type for {field}: expected {expected_type}, got {type(value)}")
                return False
        
        return True
    
    def extract_features(self, requests: List[Dict]) -> pd.DataFrame:
        """Extract features from HTTP requests for ML processing with validation"""
        try:
            features = []
            
            for req in requests:
                # Validate request data first
                if not self._validate_request_data(req):
                    logger.warning(f"Skipping invalid request: {req}")
                    continue
                
                try:
                    # Parse timestamp safely
                    timestamp_str = req.get('timestamp', '')
                    if timestamp_str:
                        try:
                            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                        except ValueError:
                            logger.warning(f"Invalid timestamp format: {timestamp_str}")
                            timestamp = datetime.now()
                    else:
                        timestamp = datetime.now()
                    
                    feature_dict = {
                        'url_length': max(0, int(req.get('url_length', 0))),
                        'body_length': max(0, int(req.get('body_length', 0))),
                        'headers_count': max(0, int(req.get('headers_count', 0))),
                        'content_length': max(0, int(req.get('content_length', 0))),
                        'has_suspicious_headers': int(bool(req.get('has_suspicious_headers', False))),
                        'contains_sql_patterns': int(bool(req.get('contains_sql_patterns', False))),
                        'contains_xss_patterns': int(bool(req.get('contains_xss_patterns', False))),
                        'method_get': int(req.get('method', '').upper() == 'GET'),
                        'method_post': int(req.get('method', '').upper() == 'POST'),
                        'method_put': int(req.get('method', '').upper() == 'PUT'),
                        'method_delete': int(req.get('method', '').upper() == 'DELETE'),
                        'hour_of_day': timestamp.hour,
                        'is_weekend': int(timestamp.weekday() >= 5)
                    }
                    features.append(feature_dict)
                    
                except Exception as e:
                    logger.error(f"Error processing request {req}: {e}")
                    continue
            
            if not features:
                logger.warning("No valid features extracted from requests")
                return pd.DataFrame()
            
            df = pd.DataFrame(features)
            
            # Store feature columns for consistency
            if not self.feature_columns:
                self.feature_columns = df.columns.tolist()
            else:
                # Ensure feature consistency
                missing_cols = set(self.feature_columns) - set(df.columns)
                if missing_cols:
                    logger.warning(f"Missing feature columns: {missing_cols}")
                    for col in missing_cols:
                        df[col] = 0
                
                # Reorder columns to match training order
                df = df[self.feature_columns]
            
            return df
            
        except Exception as e:
            logger.error(f"Error in feature extraction: {e}")
            return pd.DataFrame()
    
    def train_models(self, training_requests: List[Dict], labels: Optional[List[str]] = None):
        """Train the ML models with historical data - thread safe"""
        with self._lock:
            try:
                logger.info("Starting ML model training...")
                
                if not training_requests:
                    raise ValueError("No training data provided")
                
                # Extract features
                X = self.extract_features(training_requests)
                
                if X.empty:
                    raise ValueError("No valid features extracted from training data")
                
                logger.info(f"Extracted features from {len(X)} training samples")
                
                # Scale features
                X_scaled = self.scaler.fit_transform(X)
                
                # Train anomaly detector (unsupervised)
                self.anomaly_detector.fit(X_scaled)
                logger.info("Anomaly detector trained successfully")
                
                # Train threat classifier if labels are provided
                if labels is not None:
                    if len(labels) != len(training_requests):
                        raise ValueError(f"Labels count ({len(labels)}) must match training data count ({len(training_requests)})")
                    
                    y_encoded = self.label_encoder.fit_transform(labels)
                    
                    # For small datasets, use a smaller test split or skip train/test split
                    if len(X_scaled) < 20:
                        # Train on all data for small datasets
                        self.threat_classifier.fit(X_scaled, y_encoded)
                        logger.info(f"Threat classifier trained on {len(X_scaled)} samples (small dataset)")
                    else:
                        X_train, X_test, y_train, y_test = train_test_split(
                            X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
                        )
                        
                        self.threat_classifier.fit(X_train, y_train)
                        
                        # Evaluate model
                        y_pred = self.threat_classifier.predict(X_test)
                        logger.info("Threat Classifier Performance:")
                        logger.info(f"\n{classification_report(y_test, y_pred, target_names=self.label_encoder.classes_)}")
                else:
                    logger.warning("No labels provided - threat classifier not trained")
                
                self.is_trained = True
                self.last_training_time = datetime.now()
                logger.info("Model training completed successfully!")
                
            except Exception as e:
                logger.error(f"Model training failed: {e}")
                self.is_trained = False
                raise
    
    @retry_decorator(max_attempts=3, exceptions=(ValueError, RuntimeError))
    def predict_threats(self, requests: List[Dict]) -> List[ThreatPrediction]:
        """Predict threats for incoming requests - thread safe with comprehensive error handling"""
        with self._lock:
            try:
                # Check if threat detection feature is available
                if not degradation_manager.is_feature_available('threat_detection'):
                    logger.warning("Threat detection feature is degraded, using fallback")
                    return self._predict_threats_fallback(requests)
                
                if not self.is_trained:
                    logger.error("Models must be trained before making predictions")
                    degradation_manager.mark_feature_degraded('threat_detection')
                    return self._predict_threats_fallback(requests)
                
                if not requests:
                    return []
                
                predictions = []
                
                # Extract features with error handling
                try:
                    X = self.extract_features(requests)
                except Exception as e:
                    logger.error(f"Feature extraction failed: {e}")
                    degradation_manager.mark_feature_degraded('threat_detection')
                    return self._predict_threats_fallback(requests)
                
                if X.empty:
                    logger.warning("No valid features extracted for prediction")
                    return []
                
                # Scale features with error handling
                try:
                    X_scaled = self.scaler.transform(X)
                except Exception as e:
                    logger.error(f"Feature scaling failed: {e}")
                    degradation_manager.mark_feature_degraded('threat_detection')
                    return self._predict_threats_fallback(requests)
                
                # Get anomaly scores with error handling
                try:
                    anomaly_scores = self.anomaly_detector.decision_function(X_scaled)
                    is_anomaly = self.anomaly_detector.predict(X_scaled)
                except Exception as e:
                    logger.error(f"Anomaly detection failed: {e}")
                    # Continue with classification only
                    anomaly_scores = np.full(len(X_scaled), 0.0)
                    is_anomaly = np.zeros(len(X_scaled))
                
                # Get threat classifications with error handling
                try:
                    threat_probs = self.threat_classifier.predict_proba(X_scaled)
                    threat_classes = self.threat_classifier.predict(X_scaled)
                except Exception as e:
                    logger.error(f"Threat classification failed: {e}")
                    degradation_manager.mark_feature_degraded('threat_detection')
                    return self._predict_threats_fallback(requests)
                
                for i, req in enumerate(requests):
                    try:
                        threat_type = self.label_encoder.inverse_transform([threat_classes[i]])[0]
                        confidence = max(threat_probs[i])
                        
                        prediction = ThreatPrediction(
                            request_id=f"req_{i}_{int(datetime.now().timestamp())}",
                            threat_score=float(anomaly_scores[i]),
                            threat_type=threat_type,
                            confidence=float(confidence),
                            features_used=self.feature_columns,
                            timestamp=datetime.now()
                        )
                        predictions.append(prediction)
                        
                        # Metrics updates handled centrally by main.py to avoid conflicts
                        if METRICS_AVAILABLE and threat_type != 'normal' and confidence > 0.5:
                            logger.debug(f"Threat detected: {threat_type} (confidence: {confidence:.2f})")
                            # Metrics will be updated by main.py when threats are fetched
                        
                    except Exception as e:
                        logger.error(f"Error creating prediction for request {i}: {e}")
                        continue
                
                logger.debug(f"Generated {len(predictions)} threat predictions")
                
                # Restore feature if successful
                if predictions and degradation_manager.degraded_features:
                    degradation_manager.restore_feature('threat_detection')
                
                return predictions
                
            except Exception as e:
                logger.error(f"Critical error in threat prediction: {e}")
                degradation_manager.mark_feature_degraded('threat_detection')
                return self._predict_threats_fallback(requests)
    
    def _predict_threats_fallback(self, requests: List[Dict]) -> List[ThreatPrediction]:
        """Fallback threat prediction using rule-based approach"""
        try:
            logger.info("Using fallback rule-based threat detection")
            predictions = []
            
            for i, req in enumerate(requests):
                try:
                    # Simple rule-based threat detection
                    threat_score = 0.0
                    threat_type = "normal"
                    confidence = 0.5
                    
                    url = req.get('url', '').lower()
                    user_agent = req.get('user_agent', '').lower()
                    
                    # SQL injection patterns
                    sql_patterns = ['union', 'select', 'drop', 'insert', 'delete', '--', ';']
                    if any(pattern in url for pattern in sql_patterns):
                        threat_type = "sql_injection"
                        threat_score = -0.8
                        confidence = 0.9
                    # XSS patterns
                    else:
                        xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=']
                        if any(pattern in url for pattern in xss_patterns):
                            threat_type = "xss_attack"
                            threat_score = -0.7
                            confidence = 0.8
                        # Path traversal
                        elif '../' in url or '..\\' in url:
                            threat_type = "path_traversal"
                            threat_score = -0.6
                            confidence = 0.7
                        # Suspicious file access
                        elif any(ext in url for ext in ['.env', '.git', '.config', '/etc/']):
                            threat_type = "unauthorized_access"
                            threat_score = -0.5
                            confidence = 0.6
                        # Automated tools
                        elif any(bot in user_agent for bot in ['sqlmap', 'nikto', 'nmap', 'masscan']):
                            threat_type = "automated_attack"
                            threat_score = -0.9
                            confidence = 0.95
                    
                    prediction = ThreatPrediction(
                        request_id=f"fallback_{i}_{int(datetime.now().timestamp())}",
                        threat_score=threat_score,
                        threat_type=threat_type,
                        confidence=confidence,
                        features_used=["rule_based_fallback"],
                        timestamp=datetime.now()
                    )
                    predictions.append(prediction)
                    
                except Exception as e:
                    logger.error(f"Error in fallback prediction for request {i}: {e}")
                    continue
            
            logger.info(f"Fallback prediction generated {len(predictions)} results")
            return predictions
            
        except Exception as e:
            logger.error(f"Fallback prediction also failed: {e}")
            return []

    @retry_decorator(max_attempts=3)
    def save_models(self, model_path: str):
        """Save trained models to disk - thread safe"""
        with self._lock:
            try:
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                
                model_data = {
                    'anomaly_detector': self.anomaly_detector,
                    'threat_classifier': self.threat_classifier,
                    'scaler': self.scaler,
                    'label_encoder': self.label_encoder,
                    'feature_columns': self.feature_columns,
                    'is_trained': self.is_trained,
                    'model_version': self.model_version,
                    'last_training_time': self.last_training_time,
                    'save_timestamp': datetime.now()
                }
                
                # Save with backup
                backup_path = f"{model_path}.backup"
                if os.path.exists(model_path):
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    os.rename(model_path, backup_path)
                
                joblib.dump(model_data, model_path)
                logger.info(f"Models saved to {model_path}")
                
            except Exception as e:
                logger.error(f"Failed to save models: {e}")
                # Restore backup if save failed
                if os.path.exists(backup_path) and not os.path.exists(model_path):
                    os.rename(backup_path, model_path)
                raise
    
    def load_models(self, model_path: str):
        """Load trained models from disk - thread safe"""
        with self._lock:
            try:
                if not os.path.exists(model_path):
                    raise FileNotFoundError(f"Model file not found: {model_path}")
                
                model_data = joblib.load(model_path)
                
                # Validate loaded data
                required_keys = ['anomaly_detector', 'threat_classifier', 'scaler', 'label_encoder', 'feature_columns', 'is_trained']
                missing_keys = [key for key in required_keys if key not in model_data]
                if missing_keys:
                    raise ValueError(f"Invalid model file - missing keys: {missing_keys}")
                
                self.anomaly_detector = model_data['anomaly_detector']
                self.threat_classifier = model_data['threat_classifier']
                self.scaler = model_data['scaler']
                self.label_encoder = model_data['label_encoder']
                self.feature_columns = model_data['feature_columns']
                self.is_trained = model_data['is_trained']
                self.model_version = model_data.get('model_version', '1.0.0')
                self.last_training_time = model_data.get('last_training_time')
                
                logger.info(f"Models loaded from {model_path} (version: {self.model_version})")
                
            except Exception as e:
                logger.error(f"Failed to load models: {e}")
                self.is_trained = False
                raise
                X_train, X_test, y_train, y_test = train_test_split(
                    X_scaled, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
                )
                
                self.threat_classifier.fit(X_train, y_train)
                
                # Evaluate model
                y_pred = self.threat_classifier.predict(X_test)
                print("Threat Classifier Performance:")
                print(classification_report(y_test, y_pred, 
                                         target_names=self.label_encoder.classes_))
        
        self.is_trained = True
        print("Model training completed!")
    
    def predict_threats(self, requests: List[Dict]) -> List[ThreatPrediction]:
        """Predict threats for incoming requests"""
        if not self.is_trained:
            raise ValueError("Models must be trained before making predictions")
        
        predictions = []
        
        # Extract features
        X = self.extract_features(requests)
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores
        anomaly_scores = self.anomaly_detector.decision_function(X_scaled)
        is_anomaly = self.anomaly_detector.predict(X_scaled)
        
        # Get threat classifications
        threat_probs = self.threat_classifier.predict_proba(X_scaled)
        threat_classes = self.threat_classifier.predict(X_scaled)
        
        for i, req in enumerate(requests):
            threat_type = self.label_encoder.inverse_transform([threat_classes[i]])[0]
            confidence = max(threat_probs[i])
            
            prediction = ThreatPrediction(
                request_id=f"req_{i}_{datetime.now().timestamp()}",
                threat_score=float(anomaly_scores[i]),
                threat_type=threat_type,
                confidence=float(confidence),
                features_used=self.feature_columns,
                timestamp=datetime.now()
            )
            predictions.append(prediction)
        
        return predictions
    
    def save_models(self, model_path: str):
        """Save trained models to disk"""
        model_data = {
            'anomaly_detector': self.anomaly_detector,
            'threat_classifier': self.threat_classifier,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_columns': self.feature_columns,
            'is_trained': self.is_trained
        }
        joblib.dump(model_data, model_path)
        print(f"Models saved to {model_path}")
    
    def load_models(self, model_path: str):
        """Load trained models from disk"""
        model_data = joblib.load(model_path)
        self.anomaly_detector = model_data['anomaly_detector']
        self.threat_classifier = model_data['threat_classifier']
        self.scaler = model_data['scaler']
        self.label_encoder = model_data['label_encoder']
        self.feature_columns = model_data['feature_columns']
        self.is_trained = model_data['is_trained']
        print(f"Models loaded from {model_path}")
    
    def retrain_incremental(self, new_requests: List[Dict], new_labels: Optional[List[str]] = None):
        """Incrementally retrain models with new data"""
        if not self.is_trained:
            print("No existing models found, performing full training...")
            self.train_models(new_requests, new_labels)
            return
        
        # Extract features for new data
        X_new = self.extract_features(new_requests)
        X_new_scaled = self.scaler.transform(X_new)
        
        # Update anomaly detector (partial fit if available)
        # Note: IsolationForest doesn't support partial_fit, so we'd need to use
        # a different algorithm like SGDOneClassSVM for true incremental learning
        
        if new_labels is not None and len(new_labels) > 0:
            # For the classifier, we could implement incremental learning
            # or retrain periodically with a sliding window of data
            print("Incremental training not fully implemented for RandomForest")
            print("Consider using SGDClassifier for true online learning")
        
        print("Incremental training completed!")


class RealTimeProcessor:
    """Thread-safe real-time processor for threat detection"""
    
    def __init__(self, ml_engine: MLEngine, threat_threshold: float = 0.1):
        self.ml_engine = ml_engine
        self.threat_threshold = threat_threshold
        self.recent_threats = []
        self._lock = threading.RLock()
        self.processed_count = 0
        self.last_cleanup_time = datetime.now()
        
    def process_request(self, request_features: Dict) -> Optional[ThreatPrediction]:
        """Process a single request and return threat prediction if any"""
        with self._lock:
            try:
                if not self.ml_engine.is_trained:
                    logger.warning("ML engine not trained - cannot process requests")
                    return None
                
                # Process single request
                predictions = self.ml_engine.predict_threats([request_features])
                
                if not predictions:
                    return None
                
                prediction = predictions[0]
                
                # Check if it's a significant threat
                is_threat = (
                    prediction.threat_score < self.threat_threshold or 
                    prediction.confidence > 0.6 or 
                    prediction.threat_type != 'normal'
                )
                
                if is_threat:
                    self.recent_threats.append(prediction)
                    logger.info(f"Threat detected: {prediction.threat_type} (score: {prediction.threat_score:.3f})")
                    
                    # Cleanup old threats periodically
                    self._cleanup_old_threats()
                    
                    return prediction
                
                return None
                
            except Exception as e:
                logger.error(f"Error processing request: {e}")
                return None
    
    async def process_requests(self, requests: List[Dict]) -> List[ThreatPrediction]:
        """Process multiple requests and identify threats"""
        with self._lock:
            try:
                if not requests:
                    return []
                
                if not self.ml_engine.is_trained:
                    logger.warning("ML engine not trained - cannot process requests")
                    return []
                
                predictions = self.ml_engine.predict_threats(requests)
                
                # Filter high-threat predictions (more aggressive thresholds)
                threats = [
                    pred for pred in predictions 
                    if pred.threat_score < self.threat_threshold or 
                       pred.confidence > 0.6 or 
                       pred.threat_type != 'normal'
                ]
                
                self.recent_threats.extend(threats)
                self.processed_count += len(requests)
                
                # Cleanup old threats periodically
                self._cleanup_old_threats()
                
                logger.debug(f"Processed {len(requests)} requests, found {len(threats)} threats")
                return threats
                
            except Exception as e:
                logger.error(f"Error processing batch requests: {e}")
                return []
    
    def _cleanup_old_threats(self):
        """Remove old threats from memory"""
        now = datetime.now()
        
        # Only cleanup every 5 minutes to avoid overhead
        if (now - self.last_cleanup_time).total_seconds() < 300:
            return
        
        # Keep only threats from last hour
        cutoff_time = now.timestamp() - 3600
        old_count = len(self.recent_threats)
        
        self.recent_threats = [
            threat for threat in self.recent_threats
            if threat.timestamp.timestamp() > cutoff_time
        ]
        
        removed_count = old_count - len(self.recent_threats)
        if removed_count > 0:
            logger.debug(f"Cleaned up {removed_count} old threats")
        
        self.last_cleanup_time = now
    
    def get_recent_threats(self, limit: int = 100) -> List[ThreatPrediction]:
        """Get recent threats with optional limit"""
        with self._lock:
            self._cleanup_old_threats()
            return self.recent_threats[-limit:] if limit else self.recent_threats.copy()
    
    def get_threat_patterns(self) -> Dict[str, int]:
        """Analyze recent threats to identify patterns"""
        with self._lock:
            threat_counts = {}
            for threat in self.recent_threats:
                threat_type = threat.threat_type
                threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            
            return threat_counts
    
    def get_stats(self) -> Dict:
        """Get processor statistics"""
        with self._lock:
            return {
                'processed_requests': self.processed_count,
                'recent_threats_count': len(self.recent_threats),
                'threat_patterns': self.get_threat_patterns(),
                'last_cleanup': self.last_cleanup_time.isoformat(),
                'ml_engine_trained': self.ml_engine.is_trained
            }
