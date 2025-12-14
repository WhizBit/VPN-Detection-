# flow_processor.py
import pandas as pd
import csv
import os
from datetime import datetime
from ml_predictor import MLModelPredictor
from llm_analyzer import LLMAnalyzer

class FlowProcessor:
    def __init__(self, ml_model_type="RandomForest"):
        """
        Initialize the flow processor
        Args:
            ml_model_type: Type of ML model to use
        """
        self.ml_predictor = MLModelPredictor(ml_model_type)
        self.llm_analyzer = LLMAnalyzer()
        self.llm_results_file = "llm_analyzed_flows.csv"
        self.initialize_storage()
    
    def initialize_storage(self):
        """Initialize CSV file for storing LLM-analyzed flows"""
        headers = ["timestamp", "flow_id", "src_ip", "dst_ip", "protocol", 
                   "ml_prediction", "ml_confidence", "llm_prediction", 
                   "attack_type", "llm_confidence", "explanation"]
        
        if not os.path.exists(self.llm_results_file):
            with open(self.llm_results_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
    
    def save_llm_result(self, flow_data, ml_result, llm_result):
        """Save LLM analysis result to CSV"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            result = {
                "timestamp": timestamp,
                "flow_id": flow_data.get("Flow ID", ""),
                "src_ip": flow_data.get("Src IP", ""),
                "dst_ip": flow_data.get("Dst IP", ""),
                "protocol": flow_data.get("Protocol", ""),
                "ml_prediction": ml_result.get("label", ""),
                "ml_confidence": ml_result.get("confidence", 0),
                "llm_prediction": llm_result.get("label", ""),
                "attack_type": llm_result.get("attack_type", ""),
                "llm_confidence": llm_result.get("confidence", ""),
                "explanation": llm_result.get("explanation", "")
            }
            
            with open(self.llm_results_file, 'a', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=result.keys())
                writer.writerow(result)
                
            print(f"✅ Saved LLM analysis to {self.llm_results_file}")
            
        except Exception as e:
            print(f"❌ Error saving LLM result: {e}")
    
    def process_flow(self, flow_data):
        """
        Process a single flow through ML model and LLM if needed
        Args:
            flow_data: Dictionary containing flow statistics
        Returns:
            Dictionary with combined analysis results
        """
        print(f"\n🔍 Processing flow: {flow_data.get('Flow ID', 'Unknown')}")
        
        # Step 1: ML Model Prediction
        ml_result = self.ml_predictor.predict(flow_data)
        print(f"   ML Prediction: {ml_result['label']} (Confidence: {ml_result['confidence']:.2f})")
        
        # Step 2: Determine if LLM analysis is needed
        llm_result = None
        needs_llm_analysis = False
        
        # Skip LLM analysis if ML prediction resulted in an error
        if ml_result["label"] == "ERROR":
            print(f"   ⚠️ Skipping LLM analysis due to ML prediction error: {ml_result.get('error', 'Unknown error')}")
        # Conditions for LLM analysis:
        # 1. ML predicts "Other" or unknown class
        # 2. ML confidence is low
        # 3. ML predicts malicious activity
        elif (ml_result["label"] == "Other" or 
              ml_result["label"] == "OTHERS" or
              ml_result["confidence"] < 0.7 or 
              ml_result["is_malicious"]):
            needs_llm_analysis = True
        
        # Step 3: LLM Analysis if needed
        if needs_llm_analysis:
            print(f"   🤖 Sending to LLM for deeper analysis...")
            llm_result = self.llm_analyzer.analyze_flow(flow_data)
            print(f"   LLM Prediction: {llm_result['label']} - {llm_result.get('attack_type', '')}")
            
            # Save LLM analysis
            self.save_llm_result(flow_data, ml_result, llm_result)
        
        # Step 4: Prepare final result
        final_result = {
            **flow_data,
            "ml_prediction": ml_result["label"],
            "ml_confidence": ml_result["confidence"],
            "ml_model": ml_result["model_used"],
            "needs_llm": needs_llm_analysis
        }
        
        if llm_result:
            final_result.update({
                "llm_prediction": llm_result["label"],
                "llm_attack_type": llm_result.get("attack_type", ""),
                "llm_confidence": llm_result.get("confidence", ""),
                "llm_explanation": llm_result.get("explanation", ""),
                "final_prediction": llm_result["label"]  # Use LLM prediction as final
            })
        else:
            final_result.update({
                "llm_prediction": "Not Analyzed",
                "llm_attack_type": "",
                "llm_confidence": "",
                "llm_explanation": "",
                "final_prediction": ml_result["label"]  # Use ML prediction as final
            })
        
        return final_result