import streamlit as st
import pandas as pd
import numpy as np
import joblib

# ===============================
# PAGE CONFIG
# ===============================
st.set_page_config(
    page_title="SOC Alert Prioritization",
    layout="wide"
)

st.title("🛡️ AI-Powered SOC Alert Prioritization Dashboard")

# ===============================
# LOAD MODELS
# ===============================
@st.cache_resource
def load_models():
    priority_model = joblib.load("priority_model.joblib")
    action_model = joblib.load("action_model.joblib")
    return priority_model, action_model

priority_model, action_model = load_models()

# ===============================
# MODEL METADATA
# ===============================
FEATURES = [
    "alert_count",
    "max_severity",
    "asset_criticality",
    "lateral_movement",
    "privilege_escalation",
    "malware_detected"
]

ACTIONS = [
    "isolate_host",
    "reset_credentials",
    "run_malware_scan",
    "escalate_to_tier2"
]

# ===============================
# HELPERS
# ===============================
def priority_label(score):
    if score >= 85:
        return "High"
    elif score >= 50:
        return "Medium"
    else:
        return "Low"

def priority_color(level):
    if level == "High":
        return "background-color: #fc0356"
    elif level == "Medium":
        return "background-color: #cc6256"
    return "background-color: #8a8a8a"

# ===============================
# FILE UPLOAD
# ===============================
uploaded_file = st.file_uploader(
    "📂 Upload SOC Logs CSV",
    type=["csv"]
)

if uploaded_file:
    df = pd.read_csv(uploaded_file)

    # Validate columns
    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        st.error(f"Missing required columns: {missing}")
        st.stop()

    # Clean data
    df[FEATURES] = df[FEATURES].apply(
        pd.to_numeric, errors="coerce"
    ).fillna(0)

    X = df[FEATURES]

    # ===============================
    # PREDICTIONS
    # ===============================
    df["priority_score"] = priority_model.predict(X).round(0)
    df["priority_level"] = df["priority_score"].apply(priority_label)

    action_preds = action_model.predict(X)
    df["recommended_actions"] = [
      [a for a, v in zip(ACTIONS, row) if v == 1] or ["monitor"]
        for row in action_preds
    ]

    # ===============================
    # DASHBOARD VIEW
    # ===============================
    st.subheader("📊 SOC Alerts Overview")

    styled_df = df.style.applymap(
        priority_color, subset=["priority_level"]
    )

    st.dataframe(
        styled_df,
        use_container_width=True
    )

    # ===============================
    # INCIDENT DETAILS
    # ===============================
    st.subheader("🔍 Incident Details")

    selected_index = st.number_input(
        "Select incident row index",
        min_value=0,
        max_value=len(df) - 1,
        step=1
    )

    incident = df.iloc[int(selected_index)]

    col1, col2 = st.columns(2)

    with col1:
        st.metric("Priority Score", incident["priority_score"])
        st.metric("Priority Level", incident["priority_level"])

    with col2:
        st.write("Recommended Actions")
        for action in incident["recommended_actions"]:
            st.write(f"• {action}")


else:
    st.info("⬆️ Upload a SOC CSV file to begin")
