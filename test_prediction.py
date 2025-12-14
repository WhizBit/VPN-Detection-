import json
from ml_predictor import MLModelPredictor

def test_prediction():
    """Test if prediction works with example flow"""
    
    test_flow = {
        'Flow ID': 'test-flow-123',
        'Src IP': '192.168.1.100',
        'Dst IP': '8.8.8.8',
        'Protocol': 6,
        'Flow Duration': 1500.0,
        'Tot Fwd Pkts': 12,
        'Tot Bwd Pkts': 8,
        'TotLen Fwd Pkts': 1200,
        'TotLen Bwd Pkts': 800,
        'Tot Bytes': 2000,
        'Tot Pkts': 20,
        'FIN Flag Cnt': 1,
        'SYN Flag Cnt': 1,
        'RST Flag Cnt': 0,
        'PSH Flag Cnt': 0,
        'ACK Flag Cnt': 18,
        'URG Flag Cnt': 0,
        'ECE Flag Cnt': 0
    }
    
    print("Testing ML prediction...")
    print(f"Test flow has {len(test_flow)} features")
    
    try:
        predictor = MLModelPredictor(model_type="RandomForest", use_simple_features=True)
        
        result = predictor.predict(test_flow)
        
        print("\n" + "="*50)
        print("PREDICTION RESULT:")
        print("="*50)
        print(f"Label: {result['label']}")
        print(f"Confidence: {result['confidence']:.4f}")
        print(f"Model: {result['model_used']}")
        print(f"Malicious: {result['is_malicious']}")
        
        if result['label'] == "ERROR":
            print(f"\n❌ Error: {result.get('error', 'Unknown error')}")
            return False
        else:
            print("\n✅ Prediction successful!")
            return True
            
    except Exception as e:
        print(f"❌ Failed to make prediction: {e}")
        return False

if __name__ == "__main__":
    success = test_prediction()
    if not success:
        print("\n🔧 Recommendation: Run the simple training script first:")
        print("python train_with_flow_features.py")