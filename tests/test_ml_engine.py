import pytest
import numpy as np
from datetime import datetime
from unittest.mock import Mock, patch

from src.ml_engine import MLEngine, RealTimeProcessor, ThreatPrediction


class TestMLEngine:
    
    def setup_method(self):
        self.ml_engine = MLEngine()
    
    def test_feature_extraction(self):
        """Test feature extraction from HTTP requests"""
        requests = [
            {
                'url_length': 20,
                'body_length': 0,
                'headers_count': 5,
                'content_length': 0,
                'has_suspicious_headers': False,
                'contains_sql_patterns': True,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2024-01-01T10:00:00Z'
            },
            {
                'url_length': 15,
                'body_length': 100,
                'headers_count': 6,
                'content_length': 100,
                'has_suspicious_headers': True,
                'contains_sql_patterns': False,
                'contains_xss_patterns': True,
                'method': 'POST',
                'timestamp': '2024-01-01T11:00:00Z'
            }
        ]
        
        features_df = self.ml_engine.extract_features(requests)
        
        assert len(features_df) == 2
        assert 'url_length' in features_df.columns
        assert 'method_get' in features_df.columns
        assert 'method_post' in features_df.columns
        assert 'hour_of_day' in features_df.columns
        
        # Check feature values
        assert features_df.iloc[0]['url_length'] == 20
        assert features_df.iloc[0]['method_get'] == 1
        assert features_df.iloc[0]['method_post'] == 0
        assert features_df.iloc[0]['contains_sql_patterns'] == 1
        
        assert features_df.iloc[1]['method_get'] == 0
        assert features_df.iloc[1]['method_post'] == 1
        assert features_df.iloc[1]['contains_xss_patterns'] == 1
    
    def test_model_training(self):
        """Test ML model training"""
        # Create sample training data
        training_requests = []
        labels = []
        
        # Normal requests
        for i in range(50):
            training_requests.append({
                'url_length': np.random.randint(5, 20),
                'body_length': np.random.randint(0, 100),
                'headers_count': np.random.randint(3, 8),
                'content_length': np.random.randint(0, 100),
                'has_suspicious_headers': False,
                'contains_sql_patterns': False,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2024-01-01T10:00:00Z'
            })
            labels.append('normal')
        
        # SQL injection requests
        for i in range(25):
            training_requests.append({
                'url_length': np.random.randint(20, 50),
                'body_length': np.random.randint(0, 50),
                'headers_count': np.random.randint(3, 8),
                'content_length': np.random.randint(0, 50),
                'has_suspicious_headers': False,
                'contains_sql_patterns': True,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2024-01-01T10:00:00Z'
            })
            labels.append('sql_injection')
        
        # XSS requests
        for i in range(25):
            training_requests.append({
                'url_length': np.random.randint(15, 40),
                'body_length': np.random.randint(50, 200),
                'headers_count': np.random.randint(3, 8),
                'content_length': np.random.randint(50, 200),
                'has_suspicious_headers': True,
                'contains_sql_patterns': False,
                'contains_xss_patterns': True,
                'method': 'POST',
                'timestamp': '2024-01-01T10:00:00Z'
            })
            labels.append('xss_attack')
        
        # Train the model
        self.ml_engine.train_models(training_requests, labels)
        
        assert self.ml_engine.is_trained
        assert len(self.ml_engine.feature_columns) > 0
        assert self.ml_engine.anomaly_detector is not None
        assert self.ml_engine.threat_classifier is not None
    
    def test_threat_prediction(self):
        """Test threat prediction functionality"""
        # First train the model
        self.test_model_training()
        
        # Test prediction on new requests
        test_requests = [
            {
                'url_length': 45,
                'body_length': 0,
                'headers_count': 5,
                'content_length': 0,
                'has_suspicious_headers': False,
                'contains_sql_patterns': True,
                'contains_xss_patterns': False,
                'method': 'GET',
                'timestamp': '2024-01-01T12:00:00Z'
            }
        ]
        
        predictions = self.ml_engine.predict_threats(test_requests)
        
        assert len(predictions) == 1
        assert isinstance(predictions[0], ThreatPrediction)
        assert predictions[0].threat_type in ['normal', 'sql_injection', 'xss_attack']
        assert 0 <= predictions[0].confidence <= 1
        assert predictions[0].request_id is not None
    
    def test_model_save_load(self, tmp_path):
        """Test model saving and loading"""
        # Train model first
        self.test_model_training()
        
        # Save model
        model_path = tmp_path / "test_model.joblib"
        self.ml_engine.save_models(str(model_path))
        assert model_path.exists()
        
        # Create new engine and load model
        new_engine = MLEngine()
        assert not new_engine.is_trained
        
        new_engine.load_models(str(model_path))
        assert new_engine.is_trained
        assert len(new_engine.feature_columns) == len(self.ml_engine.feature_columns)


class TestRealTimeProcessor:
    
    def setup_method(self):
        self.ml_engine = Mock()
        self.ml_engine.predict_threats.return_value = [
            ThreatPrediction(
                request_id="test_1",
                threat_score=-0.8,
                threat_type="sql_injection",
                confidence=0.9,
                features_used=["url_length", "contains_sql_patterns"],
                timestamp=datetime.now()
            )
        ]
        
        self.processor = RealTimeProcessor(self.ml_engine, threat_threshold=-0.5)
    
    @pytest.mark.asyncio
    async def test_process_requests(self):
        """Test request processing"""
        test_requests = [
            {
                'url_length': 45,
                'contains_sql_patterns': True,
                'method': 'GET'
            }
        ]
        
        threats = await self.processor.process_requests(test_requests)
        
        assert len(threats) == 1
        assert threats[0].threat_type == "sql_injection"
        assert threats[0].threat_score < -0.5
        
        # Check that threat was added to recent_threats
        assert len(self.processor.recent_threats) == 1
    
    def test_get_threat_patterns(self):
        """Test threat pattern analysis"""
        from datetime import datetime
        
        # Add some mock threats
        self.processor.recent_threats = [
            ThreatPrediction(
                request_id="1", threat_score=-0.8, threat_type="sql_injection",
                confidence=0.9, features_used=[], timestamp=datetime.now()
            ),
            ThreatPrediction(
                request_id="2", threat_score=-0.7, threat_type="sql_injection", 
                confidence=0.8, features_used=[], timestamp=datetime.now()
            ),
            ThreatPrediction(
                request_id="3", threat_score=-0.6, threat_type="xss_attack",
                confidence=0.7, features_used=[], timestamp=datetime.now()
            )
        ]
        
        patterns = self.processor.get_threat_patterns()
        
        assert patterns["sql_injection"] == 2
        assert patterns["xss_attack"] == 1
