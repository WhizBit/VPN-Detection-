# 🛡️ VPN-Detection — AI Network Security Analyzer

Real-time network intrusion detection: a live packet sniffer turns raw traffic into flow-level statistics, a swappable ML model classifies each flow, and any flow the model is unsure about (or flags as malicious) gets a second opinion from an LLM — all surfaced on a live Streamlit dashboard.

## Architecture

```mermaid
flowchart TD
    NIC(["🌐 Network Interface<br/>live traffic"])

    subgraph CAP[" 1 · CAPTURE  —  flow_sniffer.py "]
        direction TD
        Sniffer["<b>FlowSniffer</b><br/>Scapy AsyncSniffer<br/><i>background thread, per packet</i>"]
        Agg["<b>Flow aggregation</b><br/>packets grouped by canonical<br/>(src IP, dst IP, src port, dst port, proto)"]
        Expire{{"Flow idle<br/>&gt; 5 seconds?"}}
        Stats["<b>calculate_stats()</b><br/>~40 CICFlowMeter-style features:<br/>packet-length stats · inter-arrival times<br/>TCP flag counts · header lengths · byte/pkt rates"]
        Sniffer --> Agg --> Expire
        Expire -->|"yes — expire &amp; finalize"| Stats
        Expire -.->|"no — keep buffering"| Agg
    end

    Queue[("🗂️ thread-safe Queue<br/>one dict per completed flow")]

    subgraph PROC[" 2 · PROCESSING  —  flow_processor.py "]
        direction TD
        Predictor["<b>MLModelPredictor</b><br/>choose 1 of 5 models live:<br/>RandomForest · XGBoost · GradientBoosting<br/>Neural Network (Keras) · KNN"]
        Gate{{"confidence ≥ 70%<br/>AND not malicious<br/>AND not 'Other'?"}}
        Verdict1["✅ Final verdict<br/>ML label used as-is"]
        LLM["<b>LLMAnalyzer</b><br/>Groq · llama-3.1-8b-instant<br/>structured JSON verdict:<br/>prediction · attack type · confidence · explanation"]
        Verdict2["🧠 Final verdict<br/>LLM label overrides ML label"]
        Audit[("📄 llm_analyzed_flows.csv<br/>audit log")]

        Predictor --> Gate
        Gate -->|yes| Verdict1
        Gate -->|"no — escalate"| LLM
        LLM --> Verdict2
        LLM --> Audit
    end

    subgraph DASH[" 3 · DASHBOARD  —  app.py  (Streamlit, auto-refresh 5s) "]
        direction TD
        UI["Sidebar: model switcher + live stats"]
        T1["📊 Live Dashboard"]
        T2["🚨 Threat Alerts"]
        T3["📈 Analytics<br/>(Plotly charts)"]
        T4["📋 Flow Details<br/>(filter · sort · drill-down)"]
        UI --> T1 & T2 & T3 & T4
    end

    NIC --> Sniffer
    Stats --> Queue
    Queue --> Predictor
    Verdict1 --> UI
    Verdict2 --> UI

    classDef capture fill:#1e3a5f,stroke:#4a90d9,color:#fff
    classDef process fill:#3a1e5f,stroke:#a04ad9,color:#fff
    classDef dash fill:#1e5f3a,stroke:#4ad98f,color:#fff
    classDef store fill:#5f3a1e,stroke:#d9944a,color:#fff
    class Sniffer,Agg,Expire,Stats capture
    class Predictor,Gate,Verdict1,LLM,Verdict2 process
    class UI,T1,T2,T3,T4 dash
    class Queue,Audit store
```

## How it works

**1. Live capture & flow aggregation** (`flow_sniffer.py`) — an async Scapy sniffer runs on a background thread, grouping packets into bidirectional flows keyed by a canonicalized `(src_ip, dst_ip, src_port, dst_port, protocol)` tuple so both directions of a connection map to the same flow. A second thread expires and finalizes any flow idle for more than `FLOW_TIMEOUT_SECONDS` (5s), computing ~40 CICFlowMeter-style statistics per flow — packet-length min/mean/max/std (forward and backward separately), inter-arrival times, TCP flag counts (SYN/FIN/RST/ACK/PSH/URG), header lengths, and byte/packet rates — and pushes the result onto a thread-safe queue.

**2. ML classification** (`ml_predictor.py`) — flows are pulled off the queue and scored by one of five pre-trained models (Random Forest, XGBoost, Gradient Boosting, a Keras neural network, or KNN), selectable live from the dashboard sidebar without restarting the app. Feature preprocessing handles the gap between what the live sniffer produces and what the trained model expects — deriving missing rate/ratio features on the fly and cleaning NaN/inf values — before scaling with a shared `StandardScaler` and decoding the prediction with a shared `LabelEncoder`.

**3. LLM escalation** (`llm_analyzer.py`) — a flow is routed to a Groq-hosted LLM (`llama-3.1-8b-instant` via LangChain) when the ML model's confidence drops below 70%, predicts an ambiguous `"Other"` class, or flags the flow as malicious. The LLM returns a structured verdict (prediction, attack type, confidence, explanation) that overrides the ML label as the flow's final verdict, and every LLM call is logged to `llm_analyzed_flows.csv` as an audit trail.

**4. Live dashboard** (`app.py`) — a Streamlit app with four tabs: a live-updating overview with benign/malicious counts and average confidence, a threat-alert feed, Plotly analytics (threat distribution, protocol breakdown, confidence histogram), and a filterable/sortable flow-detail table with full ML + LLM reasoning per flow. Auto-refreshes every 5 seconds.

## Model training (`train_with_flow_features.py`)

Trains against a labeled flow dataset (`combined_dataset.csv`, not included), using only the features the live sniffer can actually produce. Class imbalance is handled with SMOTE oversampling on the training split before fitting; outputs a confusion matrix and a feature-importance chart alongside the model artifact.

**Feature importance** (Random Forest, `artifacts/`):

![Feature importance](artifacts/feature_importance_top30.png)

## Tech stack

Python, Scapy, Streamlit, Plotly, scikit-learn, XGBoost, TensorFlow/Keras, imbalanced-learn (SMOTE), LangChain + Groq.

## Setup

```bash
pip install -r requirements.txt
```

Create a `.env` file with:

```
GROQ_API_KEY=your_groq_api_key
```

Packet capture requires elevated privileges (npcap on Windows, or `sudo` on Linux/Mac) and picks up your active network interface automatically via `Interface_name.py`.

Run the dashboard:

```bash
streamlit run app.py
```

## Known limitations

- **LLM escalation currently fails at runtime.** The committed `llm_analyzed_flows.csv` audit log shows every LLM call erroring out — LangChain's `ChatPromptTemplate` treats the unescaped `{` `}` braces in the JSON-format instructions inside `LLM_PROMPTS["network_analysis"]` (`config.py`) as template variables. Fix: escape them as `{{` `}}` in the prompt template.
- **Train/serve feature mismatch.** `train_with_flow_features.py` trains on a simplified 14-feature set and saves to `artifacts_simple/`, while the models actually loaded at runtime (`artifacts/`, referenced by `config.py`) expect the full 39-column `FEATURE_COLUMNS` schema — those production artifacts were trained by an earlier/unincluded script.
- Sniffing requires the app to run with elevated OS privileges, and the target interface is auto-selected as the first "up" interface, which may not always be the intended one on multi-NIC machines.

## Project structure

```
app.py                        # Streamlit dashboard (4 tabs, live auto-refresh)
flow_sniffer.py                # Scapy capture, flow aggregation, statistical features
flow_processor.py              # ML → (conditional) LLM pipeline, audit logging
ml_predictor.py                 # Loads/serves RF, XGBoost, GradBoost, NN, KNN models
llm_analyzer.py                 # Groq LLM escalation for low-confidence/malicious flows
config.py                       # Model paths, feature schema, LLM prompt templates
Interface_name.py               # Active network interface auto-detection
train_with_flow_features.py     # Offline training: SMOTE + scaling + RandomForest
test_prediction.py              # Manual smoke test for the ML predictor
artifacts/                      # Trained models, scaler, label encoder, evaluation plots
```

## Disclaimer

Built for educational / research purposes on traffic you own or have authorization to monitor.
