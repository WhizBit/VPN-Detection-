# llm_analyzer.py
import json
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from config import GROQ_API_KEY, LLM_MODEL, LLM_PROMPTS

class LLMAnalyzer:
    def __init__(self):
        """Initialize LLM analyzer"""
        if not GROQ_API_KEY:
            raise ValueError("GROQ_API_KEY not found in environment variables")
        
        self.model = ChatGroq(
            model=LLM_MODEL,
            groq_api_key=GROQ_API_KEY,
            temperature=0.3
        )
        self.output_parser = StrOutputParser()
    
    def analyze_flow(self, flow_data):
        """
        Analyze network flow using LLM
        Args:
            flow_data: Dictionary containing flow statistics
        Returns:
            Dictionary with LLM analysis results
        """
        try:
            # Format flow data for LLM
            formatted_stats = "\n".join([f"{k}: {v}" for k, v in flow_data.items()])
            
            # Create prompt
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are a cybersecurity expert analyzing network traffic."),
                ("user", LLM_PROMPTS["network_analysis"].format(flow_stats=formatted_stats))
            ])
            
            # Create chain and invoke
            chain = prompt | self.model | self.output_parser
            response = chain.invoke({})
            
            # Parse JSON response
            try:
                result = json.loads(response)
            except json.JSONDecodeError:
                # Fallback if not valid JSON
                result = {
                    "prediction": "UNKNOWN",
                    "attack_type": "Unknown",
                    "confidence": "Medium",
                    "explanation": response[:200]
                }
            
            return {
                "label": result.get("prediction", "UNKNOWN"),
                "attack_type": result.get("attack_type", "Unknown"),
                "confidence": result.get("confidence", "Medium"),
                "explanation": result.get("explanation", ""),
                "analyzer": "LLM"
            }
            
        except Exception as e:
            print(f"❌ LLM analysis error: {e}")
            return {
                "label": "ERROR",
                "attack_type": "Unknown",
                "confidence": "Low",
                "explanation": f"Analysis failed: {str(e)}",
                "analyzer": "LLM"
            }