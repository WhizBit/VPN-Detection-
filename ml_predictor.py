import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
import traceback
import os
from config import MODEL_PATHS, FEATURE_COLUMNS, SIMPLE_FEATURE_COLUMNS

class MLModelPredictor:
    def __init__(self, model_type="RandomForest", use_simple_features=True):
        """
        Initialize the ML model predictor
        Args:
            model_type: Type of model to use
            use_simple_features: Use simplified feature list for compatibility
        """
        self.model_type = model_type
        self.use_simple_features = use_simple_features
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns = SIMPLE_FEATURE_COLUMNS if use_simple_features else FEATURE_COLUMNS
        self.load_models()
    
    def load_models(self):
        """Load pre-trained models"""
        print(f"📦 Loading {self.model_type} model...")
        
        try:
            # Load scaler
            if not os.path.exists(MODEL_PATHS["Scaler"]):
                raise FileNotFoundError(f"Scaler not found at {MODEL_PATHS['Scaler']}")
            self.scaler = joblib.load(MODEL_PATHS["Scaler"])
            print(f"✅ Scaler loaded (expects {self.scaler.n_features_in_} features)")
            
            # Load label encoder
            if not os.path.exists(MODEL_PATHS["LabelEncoder"]):
                raise FileNotFoundError(f"LabelEncoder not found at {MODEL_PATHS['LabelEncoder']}")
            self.label_encoder = joblib.load(MODEL_PATHS["LabelEncoder"])
            print(f"✅ LabelEncoder loaded. Classes: {list(self.label_encoder.classes_)}")
            
            # Load model
            model_path = MODEL_PATHS.get(self.model_type)
            if not model_path:
                raise ValueError(f"Model type {self.model_type} not found")
            
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model not found at {model_path}")
            
            if self.model_type == "NeuralNetwork":
                self.model = tf.keras.models.load_model(model_path)
            else:
                self.model = joblib.load(model_path)
            
            print(f"✅ {self.model_type} model loaded successfully")
            
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            print(traceback.format_exc())
            raise
    
    def preprocess_flow(self, flow_data):
        """
        Preprocess flow data - handle missing features gracefully
        Maps flow sniffer features to model-expected features
        """
        # Clean input data first - handle NaN, None, and invalid values
        cleaned_data = {}
        for key, value in flow_data.items():
            if pd.isna(value) or value is None:
                cleaned_data[key] = 0.0
            elif isinstance(value, (int, float)):
                # Handle inf and -inf
                if np.isinf(value):
                    cleaned_data[key] = 0.0
                else:
                    cleaned_data[key] = value
            else:
                # Try to convert to numeric
                try:
                    num_val = float(value)
                    cleaned_data[key] = num_val if not np.isinf(num_val) else 0.0
                except (ValueError, TypeError):
                    cleaned_data[key] = 0.0
        
        # Convert to DataFrame
        df = pd.DataFrame([cleaned_data])
        
        # Feature mapping: flow sniffer name -> model expected name
        feature_mapping = {
            'Src Port': 'Src Port',
            'Dst Port': 'Dst Port',
            'Protocol': 'Protocol',
            'Flow Duration': 'Flow Duration',
            'Tot Fwd Pkts': 'Tot Fwd Pkts',
            'Tot Bwd Pkts': 'Tot Bwd Pkts',
            'TotLen Fwd Pkts': 'TotLen Fwd Pkts',
            'Fwd Pkt Len Max': 'Fwd Pkt Len Max',
            'Fwd Pkt Len Min': 'Fwd Pkt Len Min',
            'Bwd Pkt Len Max': 'Bwd Pkt Len Max',
            'Bwd Pkt Len Min': 'Bwd Pkt Len Min',
            'Bwd Pkt Len Mean': 'Bwd Pkt Len Mean',
            'Flow Byts/s': 'Flow Byts/s',
            'Flow Pkts/s': 'Flow Pkts/s',
            'Flow IAT Mean': 'Flow IAT Mean',
            'Flow IAT Std': 'Flow IAT Std',
            'Flow IAT Min': 'Flow IAT Min',
            'Fwd IAT Tot': 'Fwd IAT Tot',
            'Fwd IAT Mean': 'Fwd IAT Mean',
            'Fwd IAT Std': 'Fwd IAT Std',
            'Fwd IAT Min': 'Fwd IAT Min',
            'Bwd IAT Min': 'Bwd IAT Min',
            'Bwd PSH Flags': 'Bwd PSH Flags',
            'Bwd URG Flags': 'Bwd URG Flags',
            'Fwd Header Len': 'Fwd Header Len',
            'Fwd Pkts/s': 'Fwd Pkts/s',
            'Pkt Len Mean': 'Pkt Len Mean',
            'Pkt Len Var': 'Pkt Len Var',
            'FIN Flag Cnt': 'FIN Flag Cnt',
            'SYN Flag Cnt': 'SYN Flag Cnt',
            'RST Flag Cnt': 'RST Flag Cnt',
            'ACK Flag Cnt': 'ACK Flag Cnt',
            'Down/Up Ratio': 'Down/Up Ratio',
        }
        
        # Copy mapped features and clean NaN/inf values
        for model_feat, flow_feat in feature_mapping.items():
            if flow_feat in df.columns:
                val = df[flow_feat].iloc[0]
                if pd.isna(val) or np.isinf(val):
                    df[model_feat] = 0.0
                else:
                    df[model_feat] = val
        
        # Calculate derived features if possible
        missing_cols = []
        for col in self.feature_columns:
            if col not in df.columns:
                # Calculate missing features from available data
                try:
                    if col == 'Flow Byts/s':
                        if 'Tot Bytes' in df.columns and 'Flow Duration' in df.columns:
                            tot_bytes = float(df['Tot Bytes'].iloc[0]) if not pd.isna(df['Tot Bytes'].iloc[0]) else 0.0
                            duration_ms = float(df['Flow Duration'].iloc[0]) if not pd.isna(df['Flow Duration'].iloc[0]) else 0.0
                            duration_sec = max(duration_ms / 1000.0, 1e-6)
                            df[col] = tot_bytes / duration_sec
                        else:
                            df[col] = 0.0
                    elif col == 'Flow Pkts/s':
                        if 'Tot Pkts' in df.columns and 'Flow Duration' in df.columns:
                            tot_pkts = float(df['Tot Pkts'].iloc[0]) if not pd.isna(df['Tot Pkts'].iloc[0]) else 0.0
                            duration_ms = float(df['Flow Duration'].iloc[0]) if not pd.isna(df['Flow Duration'].iloc[0]) else 0.0
                            duration_sec = max(duration_ms / 1000.0, 1e-6)
                            df[col] = tot_pkts / duration_sec
                        else:
                            df[col] = 0.0
                    elif col == 'Pkt Len Mean':
                        if 'Pkt Size Avg' in df.columns:
                            val = df['Pkt Size Avg'].iloc[0]
                            df[col] = val if not (pd.isna(val) or np.isinf(val)) else 0.0
                        elif 'Tot Bytes' in df.columns and 'Tot Pkts' in df.columns:
                            tot_bytes = float(df['Tot Bytes'].iloc[0]) if not pd.isna(df['Tot Bytes'].iloc[0]) else 0.0
                            tot_pkts = float(df['Tot Pkts'].iloc[0]) if not pd.isna(df['Tot Pkts'].iloc[0]) else 0.0
                            df[col] = tot_bytes / tot_pkts if tot_pkts > 0 else 0.0
                        else:
                            df[col] = 0.0
                    elif col == 'Down/Up Ratio':
                        if 'Tot Bwd Pkts' in df.columns and 'Tot Fwd Pkts' in df.columns:
                            bwd_pkts = float(df['Tot Bwd Pkts'].iloc[0]) if not pd.isna(df['Tot Bwd Pkts'].iloc[0]) else 0.0
                            fwd_pkts = float(df['Tot Fwd Pkts'].iloc[0]) if not pd.isna(df['Tot Fwd Pkts'].iloc[0]) else 0.0
                            df[col] = bwd_pkts / fwd_pkts if fwd_pkts > 0 else 0.0
                        else:
                            df[col] = 0.0
                    elif col == 'Fwd Pkts/s':
                        if 'Tot Fwd Pkts' in df.columns and 'Flow Duration' in df.columns:
                            fwd_pkts = float(df['Tot Fwd Pkts'].iloc[0]) if not pd.isna(df['Tot Fwd Pkts'].iloc[0]) else 0.0
                            duration_ms = float(df['Flow Duration'].iloc[0]) if not pd.isna(df['Flow Duration'].iloc[0]) else 0.0
                            duration_sec = max(duration_ms / 1000.0, 1e-6)
                            df[col] = fwd_pkts / duration_sec
                        else:
                            df[col] = 0.0
                    elif col == 'Bwd Pkt Len Mean':
                        if 'Bwd Seg Size Avg' in df.columns:
                            val = df['Bwd Seg Size Avg'].iloc[0]
                            df[col] = val if not (pd.isna(val) or np.isinf(val)) else 0.0
                        elif 'TotLen Bwd Pkts' in df.columns and 'Tot Bwd Pkts' in df.columns:
                            totlen_bwd = float(df['TotLen Bwd Pkts'].iloc[0]) if not pd.isna(df['TotLen Bwd Pkts'].iloc[0]) else 0.0
                            bwd_pkts = float(df['Tot Bwd Pkts'].iloc[0]) if not pd.isna(df['Tot Bwd Pkts'].iloc[0]) else 0.0
                            df[col] = totlen_bwd / bwd_pkts if bwd_pkts > 0 else 0.0
                        else:
                            df[col] = 0.0
                    elif col == 'Pkt Len Var':
                        if 'Pkt Len Std' in df.columns:
                            std_val = df['Pkt Len Std'].iloc[0]
                            if not (pd.isna(std_val) or np.isinf(std_val)):
                                df[col] = float(std_val) * float(std_val)
                            else:
                                df[col] = 0.0
                        else:
                            df[col] = 0.0
                    # Features not generated by flow sniffer - set to default values
                    elif col in ['Init Bwd Win Byts', 'Fwd Act Data Pkts', 
                                'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Std']:
                        df[col] = 0.0  # Set missing features to 0
                    else:
                        df[col] = 0.0  # Default for any other missing feature
                    missing_cols.append(col)
                except (ValueError, TypeError, ZeroDivisionError) as e:
                    # If calculation fails, set to 0
                    df[col] = 0.0
                    missing_cols.append(col)
        
        # Ensure all features are present and in correct order
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0
        
        # Select features in correct order
        X = df[self.feature_columns].copy()
        
        # Handle NaN and inf values - replace with 0
        X = X.replace([np.inf, -np.inf], 0.0)
        X = X.fillna(0.0)
        
        # Convert to numeric, coercing errors
        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors='coerce')
            X[col] = X[col].replace([np.inf, -np.inf], 0.0)
            X[col] = X[col].fillna(0.0)
        
        # Validate that we have the right number of features
        if len(X.columns) != len(self.feature_columns):
            raise ValueError(f"Feature count mismatch: expected {len(self.feature_columns)}, got {len(X.columns)}")
        
        # Ensure feature order matches exactly
        X = X[self.feature_columns]
        
        # Scale
        try:
            X_scaled = self.scaler.transform(X)
        except Exception as e:
            raise ValueError(f"Scaling failed: {str(e)}. Features: {list(X.columns)}")
        
        return X_scaled
    
    def predict(self, flow_data):
        """Make prediction with error handling"""
        try:
            # Validate input
            if not flow_data or not isinstance(flow_data, dict):
                raise ValueError("flow_data must be a non-empty dictionary")
            
            # Check for minimum required fields
            required_fields = ['Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts']
            missing_required = [f for f in required_fields if f not in flow_data]
            if missing_required:
                raise ValueError(f"Missing required fields: {missing_required}")
            
            print(f"   Predicting with {self.model_type}...")
            
            # Preprocess
            X_processed = self.preprocess_flow(flow_data)
            
            # Validate preprocessed data
            if X_processed is None or X_processed.shape[1] != len(self.feature_columns):
                raise ValueError(f"Preprocessing failed: expected {len(self.feature_columns)} features, got {X_processed.shape[1] if X_processed is not None else 0}")
            
            # Check for NaN or inf in processed data
            if np.any(np.isnan(X_processed)) or np.any(np.isinf(X_processed)):
                X_processed = np.nan_to_num(X_processed, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Make prediction
            if self.model_type == "NeuralNetwork":
                predictions = self.model.predict(X_processed, verbose=0)
                pred_idx = np.argmax(predictions, axis=1)[0]
                confidence = float(predictions[0][pred_idx])
            else:
                if hasattr(self.model, "predict_proba"):
                    predictions = self.model.predict_proba(X_processed)
                    pred_idx = np.argmax(predictions, axis=1)[0]
                    confidence = float(predictions[0][pred_idx])
                else:
                    pred = self.model.predict(X_processed)[0]
                    pred_idx = pred
                    confidence = 1.0
            
            # Validate prediction result
            if pred_idx < 0 or pred_idx >= len(self.label_encoder.classes_):
                raise ValueError(f"Invalid prediction index: {pred_idx}")
            
            # Decode label
            label = self.label_encoder.inverse_transform([pred_idx])[0]
            
            # Validate confidence
            if not (0 <= confidence <= 1):
                confidence = max(0.0, min(1.0, confidence))
            
            print(f"   Prediction: {label} (confidence: {confidence:.3f})")
            
            # Determine if malicious (NORMAL is benign, others are malicious)
            benign_labels = ["BENIGN", "NORMAL"]
            is_malicious = label not in benign_labels
            
            return {
                "label": label,
                "confidence": confidence,
                "model_used": self.model_type,
                "is_malicious": is_malicious
            }
            
        except ValueError as e:
            # Value errors are usually data issues - log but don't print full traceback
            error_msg = str(e)
            print(f"❌ Prediction validation error: {error_msg[:150]}...")
            return {
                "label": "ERROR",
                "confidence": 0.0,
                "model_used": self.model_type,
                "is_malicious": False,
                "error": error_msg
            }
        except Exception as e:
            # Other errors - log with more detail
            error_msg = str(e)
            error_type = type(e).__name__
            print(f"❌ Prediction error ({error_type}): {error_msg[:150]}...")
            import traceback
            print(traceback.format_exc()[:300])  # Print first part of traceback
            return {
                "label": "ERROR",
                "confidence": 0.0,
                "model_used": self.model_type,
                "is_malicious": False,
                "error": f"{error_type}: {error_msg}"
            }