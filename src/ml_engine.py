"""
ML Engine Module

Handles real-time machine learning for threat detection and analysis.
"""

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
    """Real-time machine learning engine for threat detection"""
    
    def __init__(self):
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.threat_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.is_trained = False
        
    def extract_features(self, requests: List[Dict]) -> pd.DataFrame:
        """Extract features from HTTP requests for ML processing"""
        features = []
        
        for req in requests:
            feature_dict = {
                'url_length': req.get('url_length', 0),
                'body_length': req.get('body_length', 0),
                'headers_count': req.get('headers_count', 0),
                'content_length': req.get('content_length', 0),
                'has_suspicious_headers': int(req.get('has_suspicious_headers', False)),
                'contains_sql_patterns': int(req.get('contains_sql_patterns', False)),
                'contains_xss_patterns': int(req.get('contains_xss_patterns', False)),
                'method_get': int(req.get('method') == 'GET'),
                'method_post': int(req.get('method') == 'POST'),
                'method_put': int(req.get('method') == 'PUT'),
                'method_delete': int(req.get('method') == 'DELETE'),
                'hour_of_day': datetime.fromisoformat(req.get('timestamp')).hour,
                'is_weekend': int(datetime.fromisoformat(req.get('timestamp')).weekday() >= 5)
            }
            features.append(feature_dict)
        
        df = pd.DataFrame(features)
        self.feature_columns = df.columns.tolist()
        return df
    
    def train_models(self, training_requests: List[Dict], labels: Optional[List[str]] = None):
        """Train the ML models with historical data"""
        print("Training ML models...")
        
        # Extract features
        X = self.extract_features(training_requests)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train anomaly detector (unsupervised)
        self.anomaly_detector.fit(X_scaled)
        
        # Train threat classifier if labels are provided
        if labels is not None:
            y_encoded = self.label_encoder.fit_transform(labels)
            
            # For small datasets, use a smaller test split or skip train/test split
            if len(X_scaled) < 20:
                # Train on all data for small datasets
                self.threat_classifier.fit(X_scaled, y_encoded)
                print(f"Model trained on {len(X_scaled)} samples (small dataset - using all data for training)")
            else:
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
    """Processes requests in real-time and triggers WAF rule generation"""
    
    def __init__(self, ml_engine: MLEngine, threat_threshold: float = 0.1):
        self.ml_engine = ml_engine
        self.threat_threshold = threat_threshold
        self.recent_threats = []
    
    async def process_requests(self, requests: List[Dict]) -> List[ThreatPrediction]:
        """Process requests and identify threats"""
        if not requests:
            return []
        
        predictions = self.ml_engine.predict_threats(requests)
        
        # Filter high-threat predictions (more aggressive thresholds)
        threats = [
            pred for pred in predictions 
            if pred.threat_score < 0.2 or pred.confidence > 0.3 or pred.threat_type != 'normal'
        ]
        
        self.recent_threats.extend(threats)
        
        # Keep only recent threats (last hour)
        cutoff_time = datetime.now().timestamp() - 3600
        self.recent_threats = [
            threat for threat in self.recent_threats
            if threat.timestamp.timestamp() > cutoff_time
        ]
        
        return threats
    
    def get_threat_patterns(self) -> Dict[str, int]:
        """Analyze recent threats to identify patterns"""
        threat_counts = {}
        for threat in self.recent_threats:
            threat_type = threat.threat_type
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
        return threat_counts
