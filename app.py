import pandas as pd
import streamlit as st
from scapy.all import sniff, IP, TCP, UDP
import threading
import queue
import time
import numpy as np
import joblib
from tensorflow.keras.models import load_model
import socket
import struct

# Load model and preprocessing tools
model = load_model("model/lstm_model.h5")
scaler = joblib.load("model/scaler.pkl")
label_encoder = joblib.load("model/label_encoder.pkl")

# Page config
st.set_page_config(layout="wide")
st.title("🧠 Live Packet Monitor with LSTM Intrusion Detection")

# Shared queue and session init
packet_queue = queue.Queue()
packet_history = []

if "run_sniffer" not in st.session_state:
    st.session_state.run_sniffer = False
if "interface" not in st.session_state:
    st.session_state.interface = "Wi-Fi"

# Sidebar controls
with st.sidebar:
    st.session_state.interface = st.text_input("Interface", value=st.session_state.interface)
    if st.button("Start Sniffing"):
        st.session_state.run_sniffer = True
    if st.button("Stop Sniffing"):
        st.session_state.run_sniffer = False

# IP conversion
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

# Extract 12 flow-based features
def extract_flow_features(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    now = pkt.time
    packet_history.append((now, pkt))
    packet_history[:] = packet_history[-30:]

    timestamps = [t for t, _ in packet_history]
    rev_timestamps = [t for t, p in packet_history if IP in p and p[IP].src != ip.src]

    flow_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
    flow_pkts_per_sec = len(timestamps) / flow_duration if flow_duration > 0 else 0
    flow_iat_mean = np.mean(np.diff(timestamps)) if len(timestamps) > 1 else 0
    bwd_iat_total = sum(np.diff(rev_timestamps)) if len(rev_timestamps) > 1 else 0
    bwd_iat_mean = np.mean(np.diff(rev_timestamps)) if len(rev_timestamps) > 1 else 0
    bwd_iat_max = max(np.diff(rev_timestamps)) if len(rev_timestamps) > 1 else 0

    bwd_header_len = 0
    bwd_pkts_per_sec = len(rev_timestamps) / flow_duration if flow_duration > 0 else 0
    init_bwd_win_bytes = 0
    dst_port = 0

    if TCP in pkt:
        dst_port = pkt[TCP].dport
        init_bwd_win_bytes = pkt[TCP].window if ip.src != pkt[IP].src else 0
    elif UDP in pkt:
        dst_port = pkt[UDP].dport

    features = [
        ip_to_int(ip.src),
        ip_to_int(ip.dst),
        dst_port,
        flow_duration,
        flow_pkts_per_sec,
        flow_iat_mean,
        bwd_iat_total,
        bwd_iat_mean,
        bwd_iat_max,
        bwd_header_len,
        bwd_pkts_per_sec,
        init_bwd_win_bytes
    ]
    return features

def predict_packet(features):
    try:

        columns = [
            "Src IP", "Dst IP", "Dst Port", "Flow Duration", "Flow Pkts/s",
            "Flow IAT Mean", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Max",
            "Bwd Header Len", "Bwd Pkts/s", "Init Bwd Win Byts"
        ]


        df_features = pd.DataFrame([features], columns=columns)


        scaled = scaler.transform(df_features)
        reshaped = scaled.reshape(1, 1, -1)

        # Predict
        prediction = model.predict(reshaped)
        pred_class = np.argmax(prediction)
        label = label_encoder.inverse_transform([pred_class])[0]
        return label
    except Exception as e:
        print("Prediction error:", e)
        return "Error"


# Sniff callback
def packet_callback(pkt):
    packet_queue.put(pkt)

def start_sniffing(interface):
    sniff(iface=interface, prn=packet_callback, store=False)

# Start thread if needed
if st.session_state.run_sniffer:
    if "sniffer_thread" not in st.session_state or not st.session_state.sniffer_thread.is_alive():
        thread = threading.Thread(target=start_sniffing, args=(st.session_state.interface,), daemon=True)
        thread.start()
        st.session_state.sniffer_thread = thread

# Live display
st.subheader("📡 Real-Time Packet Analysis")
log_area = st.empty()
rate_display = st.empty()
logs = []

headers = [
    "Src IP", "Dst IP", "Dst Port", "Flow Duration", "Flow Pkts/s",
    "Flow IAT Mean", "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Max",
    "Bwd Header Len", "Bwd Pkts/s", "Init Bwd Win Byts", "Status"
]

t_last = time.time()
count = 0
current_rate = 0.0

try:
    while st.session_state.run_sniffer:
        try:
            pkt = packet_queue.get(timeout=1)
        except queue.Empty:
            pkt = None

        if pkt:
            feats = extract_flow_features(pkt)
            if feats:
                label_map = {
                    0: "BFA",
                    1: "BOTNET",
                    2: "DDOS",
                    3: "DDOS",
                    4: "DOS",
                    5: "Normal",
                    6: "Probe",
                    7: "U2R",
                    8: "Web Attack"
                }
                prediction = predict_packet(feats)
                if isinstance(prediction, str) and prediction == "Error":
                    status = "⚠️ Error"
                    display_label = "Unknown"
                else:
                    pred_index = label_encoder.transform([prediction])[0] if isinstance(prediction, str) else prediction
                    attack_name = label_map.get(pred_index, "Unknown")
                    status = "✅ SAFE" if pred_index == 5 else f"❌ ATTACK: {attack_name}"

                    short_log = f"{time.strftime('%H:%M:%S')} | {attack_name} | {status}"
                    log_line = f"{short_log} | " + ", ".join(
                        f"{name}: {val:.2f}" if isinstance(val, float) else f"{name}: {val}"
                        for name, val in zip(headers[:-1], feats)
                    )
                    logs.append(log_line)
                count += 1
                if len(logs) > 60:
                    logs.pop(0)

        now = time.time()
        if now - t_last >= 1.0:
            current_rate = count / (now - t_last)
            count = 0
            t_last = now

        rate_display.metric("Packets/sec", f"{current_rate:.1f}")
        log_area.text("\n".join(logs))
        time.sleep(0.1)

finally:
    st.info("Click 'Start Sniffing' to begin.")
