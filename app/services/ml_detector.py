import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, List
import joblib
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class MLFraudDetector:
    """Machine Learning-based fraud detection system"""
    
    def __init__(self):
        self.isolation_forest = None
        self.random_forest = None
        self.tfidf_vectorizer = None
        self.scaler = None
        self.is_initialized = False
        self.model_path = "./models"
        
        # Create models directory if it doesn't exist
        os.makedirs(self.model_path, exist_ok=True)
    
    async def initialize(self):
        """Initialize or load ML models"""
        try:
            await self._load_or_create_models()
            self.is_initialized = True
            logger.info("ML Fraud Detector initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize ML Fraud Detector: {str(e)}")
            # Create basic models as fallback
            await self._create_default_models()
            self.is_initialized = True
    
    async def _load_or_create_models(self):
        """Load existing models or create new ones"""
        model_files = {
            'isolation_forest': os.path.join(self.model_path, 'isolation_forest.pkl'),
            'random_forest': os.path.join(self.model_path, 'random_forest.pkl'),
            'tfidf_vectorizer': os.path.join(self.model_path, 'tfidf_vectorizer.pkl'),
            'scaler': os.path.join(self.model_path, 'scaler.pkl')
        }
        
        # Check if all model files exist
        all_exist = all(os.path.exists(path) for path in model_files.values())
        
        if all_exist:
            try:
                self.isolation_forest = joblib.load(model_files['isolation_forest'])
                self.random_forest = joblib.load(model_files['random_forest'])
                self.tfidf_vectorizer = joblib.load(model_files['tfidf_vectorizer'])
                self.scaler = joblib.load(model_files['scaler'])
                logger.info("Loaded existing ML models")
                return
            except Exception as e:
                logger.warning(f"Failed to load existing models: {str(e)}. Creating new ones.")
        
        # Create new models
        await self._create_default_models()
        await self._save_models()
    
    async def _create_default_models(self):
        """Create default ML models with synthetic training data"""
        # Generate synthetic training data for demonstration
        synthetic_data = self._generate_synthetic_training_data()
        
        # Initialize models
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        
        self.random_forest = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=10
        )
        
        self.tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words='english',
            ngram_range=(1, 2)
        )
        
        self.scaler = StandardScaler()
        
        # Train models
        X, y, text_features = synthetic_data
        
        # Fit the scaler and transform numerical features
        X_scaled = self.scaler.fit_transform(X)
        
        # Fit TF-IDF vectorizer on text features
        text_vectors = self.tfidf_vectorizer.fit_transform(text_features)
        
        # Combine features
        combined_features = np.hstack([X_scaled, text_vectors.toarray()])
        
        # Train models
        self.isolation_forest.fit(combined_features)
        self.random_forest.fit(combined_features, y)
        
        logger.info("Created and trained default ML models")
    
    def _generate_synthetic_training_data(self):
        """Generate synthetic training data for model initialization"""
        np.random.seed(42)
        n_samples = 1000
        
        # Generate numerical features
        file_sizes = np.random.lognormal(10, 2, n_samples)  # File sizes
        string_counts = np.random.poisson(50, n_samples)    # Number of strings
        entropy_scores = np.random.beta(2, 5, n_samples)    # File entropy
        
        # Generate labels (0 = benign, 1 = malicious)
        labels = np.random.binomial(1, 0.1, n_samples)  # 10% malicious
        
        # Make malicious files have different characteristics
        malicious_mask = labels == 1
        file_sizes[malicious_mask] *= np.random.uniform(0.5, 2.0, np.sum(malicious_mask))
        string_counts[malicious_mask] *= np.random.uniform(1.5, 3.0, np.sum(malicious_mask))
        entropy_scores[malicious_mask] = np.random.beta(5, 2, np.sum(malicious_mask))
        
        # Combine numerical features
        X = np.column_stack([file_sizes, string_counts, entropy_scores])
        
        # Generate text features (simulated extracted strings)
        benign_words = ['version', 'copyright', 'microsoft', 'windows', 'system', 'file', 'data']
        malicious_words = ['password', 'keylog', 'bitcoin', 'crypto', 'hack', 'virus', 'trojan']
        
        text_features = []
        for i in range(n_samples):
            if labels[i] == 0:  # Benign
                words = np.random.choice(benign_words, size=np.random.randint(3, 8))
            else:  # Malicious
                words = np.random.choice(malicious_words, size=np.random.randint(2, 6))
            text_features.append(' '.join(words))
        
        return X, labels, text_features
    
    async def _save_models(self):
        """Save trained models to disk"""
        try:
            joblib.dump(self.isolation_forest, os.path.join(self.model_path, 'isolation_forest.pkl'))
            joblib.dump(self.random_forest, os.path.join(self.model_path, 'random_forest.pkl'))
            joblib.dump(self.tfidf_vectorizer, os.path.join(self.model_path, 'tfidf_vectorizer.pkl'))
            joblib.dump(self.scaler, os.path.join(self.model_path, 'scaler.pkl'))
            logger.info("Models saved successfully")
        except Exception as e:
            logger.error(f"Failed to save models: {str(e)}")
    
    async def analyze_file(self, file_path: str, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file using ML models"""
        if not self.is_initialized:
            return {
                'error': 'ML detector not initialized',
                'confidence': 0.0,
                'is_anomaly': False,
                'prediction': 'unknown'
            }
        
        try:
            # Extract features from file info
            features = self._extract_features(file_info)
            
            # Prepare features for model
            numerical_features = features['numerical']
            text_features = features['text']
            
            # Transform features
            X_scaled = self.scaler.transform([numerical_features])
            text_vector = self.tfidf_vectorizer.transform([text_features])
            
            # Combine features
            combined_features = np.hstack([X_scaled, text_vector.toarray()])
            
            # Get predictions
            anomaly_score = self.isolation_forest.decision_function(combined_features)[0]
            is_anomaly = self.isolation_forest.predict(combined_features)[0] == -1
            
            rf_prediction = self.random_forest.predict(combined_features)[0]
            rf_probability = self.random_forest.predict_proba(combined_features)[0]
            
            # Calculate confidence score
            confidence = max(rf_probability)
            
            # Combine predictions
            is_malicious = is_anomaly or rf_prediction == 1
            
            return {
                'confidence': float(confidence),
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(anomaly_score),
                'rf_prediction': int(rf_prediction),
                'rf_probability': rf_probability.tolist(),
                'is_malicious': is_malicious,
                'features_used': list(features.keys()),
                'model_version': '1.0',
                'analysis_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"ML analysis error: {str(e)}")
            return {
                'error': str(e),
                'confidence': 0.0,
                'is_anomaly': False,
                'prediction': 'error'
            }
    
    def _extract_features(self, file_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract features from file information for ML analysis"""
        
        # Numerical features
        file_size = file_info.get('file_size', 0)
        string_count = len(file_info.get('extracted_strings', []))
        suspicious_indicator_count = len(file_info.get('suspicious_indicators', []))
        
        # Calculate file entropy (simplified)
        entropy = self._calculate_entropy(file_info.get('file_path', ''))
        
        numerical_features = [
            np.log(max(file_size, 1)),  # Log file size
            string_count,
            suspicious_indicator_count,
            entropy
        ]
        
        # Text features (combine extracted strings)
        extracted_strings = file_info.get('extracted_strings', [])
        text_features = ' '.join(extracted_strings[:50])  # Limit text length
        
        # Add metadata text
        metadata = file_info.get('metadata', {})
        if isinstance(metadata, dict):
            for key, value in metadata.items():
                if isinstance(value, str):
                    text_features += f" {value}"
        
        return {
            'numerical': numerical_features,
            'text': text_features
        }
    
    def _calculate_entropy(self, file_path: str) -> float:
        """Calculate Shannon entropy of file (simplified implementation)"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Sample first 1KB
            
            if not data:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * np.log2(probability)
            
            return entropy
            
        except Exception:
            return 0.0
    
    async def retrain_model(self, feedback_data: List[Dict[str, Any]]):
        """Retrain model based on user feedback"""
        try:
            if not feedback_data:
                return
            
            # Process feedback data for retraining
            # This is a simplified implementation
            logger.info(f"Processing {len(feedback_data)} feedback entries for model improvement")
            
            # In a production system, you would:
            # 1. Convert feedback to training data
            # 2. Combine with existing training data
            # 3. Retrain models
            # 4. Validate new model performance
            # 5. Deploy if better than current model
            
            # For now, just log the feedback
            for feedback in feedback_data:
                logger.info(f"Feedback: {feedback}")
            
        except Exception as e:
            logger.error(f"Model retraining error: {str(e)}")
    
    def get_model_stats(self) -> Dict[str, Any]:
        """Get model statistics and information"""
        return {
            'is_initialized': self.is_initialized,
            'model_version': '1.0',
            'models_available': {
                'isolation_forest': self.isolation_forest is not None,
                'random_forest': self.random_forest is not None,
                'tfidf_vectorizer': self.tfidf_vectorizer is not None,
                'scaler': self.scaler is not None
            },
            'last_updated': datetime.utcnow().isoformat()
        }