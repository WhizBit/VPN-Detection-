# config.py
import os
from dotenv import load_dotenv

load_dotenv()

# Model paths
ARTIFACT_DIR = "artifacts"
MODEL_PATHS = {
    "RandomForest": os.path.join(ARTIFACT_DIR, "RandomForest.joblib"),
    "GradientBoosting": os.path.join(ARTIFACT_DIR, "GradientBoosting.joblib"),
    "XGBoost": os.path.join(ARTIFACT_DIR, "XGBoost.joblib"),
    "KNN": os.path.join(ARTIFACT_DIR, "KNN.joblib"),
    "NeuralNetwork": os.path.join(ARTIFACT_DIR, "nn_model.keras"),
    "Scaler": os.path.join(ARTIFACT_DIR, "scaler.joblib"),
    "LabelEncoder": os.path.join(ARTIFACT_DIR, "label_encoder.joblib")
}

# LLM Config
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
LLM_MODEL = "llama-3.1-8b-instant"

# Feature columns that the trained model expects (from scaler.feature_names_in_)
# This must match exactly what the model was trained with
FEATURE_COLUMNS = [
    'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts',
    'Tot Bwd Pkts', 'TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min',
    'Bwd Pkt Len Max', 'Bwd Pkt Len Min', 'Bwd Pkt Len Mean', 'Flow Byts/s',
    'Flow Pkts/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Min',
    'Fwd IAT Tot', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Min', 'Bwd IAT Min',
    'Bwd PSH Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Fwd Pkts/s',
    'Pkt Len Mean', 'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt',
    'RST Flag Cnt', 'ACK Flag Cnt', 'Down/Up Ratio', 'Init Bwd Win Byts',
    'Fwd Act Data Pkts', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Std'
]

# Alternative: Simple feature list for testing (if above doesn't work)
SIMPLE_FEATURE_COLUMNS = FEATURE_COLUMNS  # Use same as main features

# LLM prompts for network flow analysis
LLM_PROMPTS = {
    "network_analysis": """
    You are a cybersecurity expert analyzing network traffic patterns. 
    Given the following network flow statistics, classify if this flow is malicious or benign.
    If malicious, specify the type of attack (DDOS, Port Scan, Brute Force, etc.).
    
    Flow Statistics:
    {flow_stats}
    
    Provide output in this JSON format:
    {{
        "prediction": "BENIGN" or "MALICIOUS",
        "attack_type": "Type of attack if malicious, otherwise 'None'",
        "confidence": "High/Medium/Low",
        "explanation": "Brief explanation of your analysis"
    }}
    """
}