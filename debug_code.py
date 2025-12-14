# debug_features.py
import pandas as pd
import numpy as np
import os
import joblib

ARTIFACT_DIR = "artifacts"

def check_feature_alignment():
    """Check what features the model expects vs what flow sniffer provides"""
    
    # Load the scaler to see what features it expects
    scaler_path = os.path.join(ARTIFACT_DIR, "scaler.joblib")
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
        print(f"✅ Scaler loaded. It expects {scaler.n_features_in_} features")
        
        # Try to find feature names (they might be saved separately)
        feature_imp_path = os.path.join(ARTIFACT_DIR, "feature_importances.csv")
        if os.path.exists(feature_imp_path):
            feat_imp = pd.read_csv(feature_imp_path)
            print(f"✅ Feature importances loaded. {len(feat_imp)} features")
            print("Top 20 features:")
            print(feat_imp.head(20))
            
            # These are the features the model was trained on
            model_features = feat_imp['Unnamed: 0'].tolist() if 'Unnamed: 0' in feat_imp.columns else feat_imp.index.tolist()
            print(f"\n📋 Model expects these {len(model_features)} features:")
            for i, feat in enumerate(model_features[:20]):
                print(f"  {i+1:2d}. {feat}")
    else:
        print("❌ Scaler not found!")
    
    # Now check what features flow sniffer actually generates
    print("\n" + "="*60)
    print("FLOW SNIFFER FEATURES ANALYSIS")
    print("="*60)
    
    # Example flow from your sniffer (from the error screenshot)
    example_flow = {
        'Flow ID': '104.20.25.157-172.16.141.119-443-63993-TCP',
        'Src IP': '104.20.25.157',
        'Src Port': 443,
        'Dst IP': '172.16.141.119',
        'Dst Port': 63993,
        'Protocol': 6,
        'Timestamp': 1698765432.1,
        'Flow Duration': 1234.5,
        'Tot Fwd Pkts': 10,
        'Tot Bwd Pkts': 5,
        'Tot Pkts': 15,
        'Tot Bytes': 1500,
        'TotLen Fwd Pkts': 1000,
        'TotLen Bwd Pkts': 500,
        'Fwd Pkt Len Max': 200,
        'Fwd Pkt Len Min': 50,
        'Fwd Pkt Len Mean': 100.0,
        'Fwd Pkt Len Std': 50.0,
        'Bwd Pkt Len Max': 150,
        'Bwd Pkt Len Min': 30,
        'Bwd Pkt Len Mean': 75.0,
        'Bwd Pkt Len Std': 40.0,
        'Flow Byts/s': 1215.0,
        'Flow Pkts/s': 12.15,
        'Flow IAT Mean': 82.3,
        'Flow IAT Std': 45.6,
        'Flow IAT Max': 200.0,
        'Flow IAT Min': 10.0,
        'Fwd IAT Tot': 500.0,
        'Fwd IAT Mean': 50.0,
        'Fwd IAT Std': 25.0,
        'Fwd IAT Max': 100.0,
        'Fwd IAT Min': 10.0,
        'Bwd IAT Tot': 400.0,
        'Bwd IAT Mean': 80.0,
        'Bwd IAT Std': 35.0,
        'Bwd IAT Max': 150.0,
        'Bwd IAT Min': 20.0,
        'Fwd PSH Flags': 0,
        'Bwd PSH Flags': 0,
        'Fwd URG Flags': 0,
        'Bwd URG Flags': 0,
        'Fwd Header Len': 160,
        'Bwd Header Len': 80,
        'Fwd Pkts/s': 8.1,
        'Bwd Pkts/s': 4.05,
        'Pkt Len Min': 30,
        'Pkt Len Max': 200,
        'Pkt Len Mean': 87.5,
        'Pkt Len Std': 45.0,
        'Pkt Len Var': 2025.0,
        'FIN Flag Cnt': 1,
        'SYN Flag Cnt': 1,
        'RST Flag Cnt': 0,
        'PSH Flag Cnt': 0,
        'ACK Flag Cnt': 10,
        'URG Flag Cnt': 0,
        'ECE Flag Cnt': 0,
        'Down/Up Ratio': 0.5,
        'Pkt Size Avg': 87.5,
        'Fwd Seg Size Avg': 100.0,
        'Bwd Seg Size Avg': 75.0,
        'Init Fwd Win Byts': 65535
    }
    
    print(f"Example flow has {len(example_flow)} features")
    print("\nFlow features (alphabetical):")
    flow_features = sorted(list(example_flow.keys()))
    for i, feat in enumerate(flow_features):
        print(f"  {i+1:2d}. {feat}")
    
    return example_flow

if __name__ == "__main__":
    check_feature_alignment()