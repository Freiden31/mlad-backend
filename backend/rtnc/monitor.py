import threading
import os
from dotenv import load_dotenv
import requests
import paramiko
import numpy as np
from .models import Packets

# ------------------- Load environment variables -------------------
load_dotenv()
MODEL_URL = os.getenv("MODEL_URL")
if not MODEL_URL:
    raise ValueError("[ERROR] MODEL_URL not found in .env file!")
print(f"[DEBUG] MODEL_URL loaded: {MODEL_URL}")
# ------------------------------------------------------------------

monitoring_active = False
monitor_thread = None
ssh_client = None
ssh_config = {}

# 🔹 Model expected feature order (exact)
FEATURE_ORDER = ['Protocol', 'Fwd Packet Length Min', 'Fwd Packet Length Std',
       'Bwd Packet Length Min', 'Flow Bytes/s', 'Flow IAT Min', 'Fwd IAT Mean',
       'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Max', 'Bwd IAT Min',
       'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
       'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
       'Packet Length Min', 'Packet Length Variance', 'FIN Flag Count',
       'SYN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
       'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
       'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk',
       'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
       'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Bytes',
       'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes',
       'Fwd Act Data Packets', 'Fwd Seg Size Min', 'Active Std', 'Active Max',
       'Active Min', 'Idle Std', 'Idle Min']
# 🔹 Mapping for Django model fields
FEATURE_KEY_MAP = {
    "Protocol" : "protocol",
    'Fwd Packet Length Min' : 'fwd_packet_length_min', 
    'Fwd Packet Length Std': 'fwd_packet_length_std',
    'Bwd Packet Length Min' : 'bwd_packet_length_min', 
    'Flow Bytes/s' : 'flow_bytes_s', 
    'Flow IAT Min' : 'flow_iat_min', 
    'Fwd IAT Mean' : 'fwd_iat_mean',
    'Fwd IAT Min' : 'fwd_iat_min', 
    'Bwd IAT Total' : 'bwd_iat_total', 
    'Bwd IAT Max' : 'bwd_iat_max', 
    'Bwd IAT Min' : 'bwd_iat_min',
    'Bwd PSH Flags' : 'bwd_psh_flags', 
    'Fwd URG Flags' : 'fwd_urg_flags', 
    'Bwd URG Flags' : 'bwd_urg_flags', 
    'Fwd Header Length' : 'fwd_header_length',
    'Bwd Header Length' : 'bwd_header_length', 
    'Fwd Packets/s' : 'fwd_packets_s', 
    'Bwd Packets/s' : 'bwd_packets_s',
    'Packet Length Min' : 'packet_length_min', 
    'Packet Length Variance' : 'packet_length_variance', 
    'FIN Flag Count' : 'fin_flag_count',
    'SYN Flag Count' : 'syn_flag_count', 
    'PSH Flag Count' : 'psh_flag_count', 
    'ACK Flag Count' : 'ack_flag_count', 
    'URG Flag Count' : 'urg_flag_count',
    'CWE Flag Count' : 'cwe_flag_count', 
    'ECE Flag Count' : 'ece_flag_count', 
    'Down/Up Ratio' : 'down_up_ratio',
    'Avg Fwd Segment Size' : 'avg_fwd_segment_size', 
    'Avg Bwd Segment Size' : 'avg_bwd_segment_size', 
    'Fwd Avg Bytes/Bulk' : 'fwd_avg_bytes_bulk',
    'Fwd Avg Packets/Bulk' : 'fwd_avg_packets_bulk', 
    'Fwd Avg Bulk Rate' : 'fwd_avg_bulk_rate', 
    'Bwd Avg Bytes/Bulk' : 'bwd_avg_bytes_bulk',
    'Bwd Avg Packets/Bulk' : 'bwd_avg_packets_bulk', 
    'Bwd Avg Bulk Rate' : 'bwd_avg_bulk_rate', 
    'Subflow Fwd Bytes' : 'subflow_fwd_bytes',
    'Subflow Bwd Bytes' : 'subflow_bwd_bytes', 
    'Init Fwd Win Bytes' : 'init_fwd_win_bytes', 
    'Init Bwd Win Bytes' : 'init_bwd_win_bytes',
    'Fwd Act Data Packets' : 'fwd_act_data_packets', 
    'Fwd Seg Size Min' : 'fwd_seg_size_min', 
    'Active Std' : 'active_std', 
    'Active Max' : 'active_max',
    'Active Min' : 'active_min', 
    'Idle Std' : 'idle_std', 
    'Idle Min' : 'idle_min'
}

# ------------------- SSH Management -------------------
def set_ssh_credentials(host, username, password):
    global ssh_config
    ssh_config = {'host': host, 'username': username, 'password': password}
    print(f"[DEBUG] SSH credentials set for {username}@{host}")

def setup_ssh():
    global ssh_client
    if not ssh_config:
        print("[ERROR] SSH credentials not set.")
        return None
    print("[DEBUG] Setting up SSH connection...")
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        ssh_config['host'],
        username=ssh_config['username'],
        password=ssh_config['password']
    )
    print("[DEBUG] SSH connection established successfully.")
    return ssh_client

def run_command_stream(ssh, cmd):
    print(f"[DEBUG] Running command: {cmd}")
    transport = ssh.get_transport()
    channel = transport.open_session()
    channel.get_pty()
    channel.exec_command(cmd)
    return channel.makefile("r")

# ------------------- Packet Parsing -------------------
def parse_flags(flags_str):
    flag_init = int(flags_str, 16) if flags_str else 0
    return {
        'FIN': int(bool(flag_init & 0x1)),
        'SYN': int(bool(flag_init & 0x2)),
        'RST': int(bool(flag_init & 0x4)),
        'PSH': int(bool(flag_init & 0x8)),
        'ACK': int(bool(flag_init & 0x10)),
        'URG': int(bool(flag_init & 0x20)),
        'ECE': int(bool(flag_init & 0x40)),
        'CWR': int(bool(flag_init & 0x80)),
    }

def add_packet_to_flow(flows, packet):
    key = (packet['src_ip'], packet['dst_ip'], packet['src_port'], packet['dst_port'], packet['proto'])
    rev_key = (packet['dst_ip'], packet['src_ip'], packet['dst_port'], packet['src_port'], packet['proto'])
    for k in (key, rev_key):
        if k in flows:
            flows[k].append(packet)
            return k
    flows[key] = [packet]
    return key

# ------------------- Feature Extraction -------------------
def compute_flow_features(packets):
    if not packets:
        return {}

    times = np.array([p['time'] for p in packets], dtype=float)
    lengths = np.array([p['len'] for p in packets], dtype=float)
    protocol = float(packets[0]['proto'])
    flow_duration = float(times[-1] - times[0]) if len(times) > 1 else 1e-6

    fwd_ip, bwd_ip = packets[0]['src_ip'], packets[0]['dst_ip']
    fwd_port, bwd_port = packets[0]['src_port'], packets[0]['dst_port']

    fwd_pkts = [p for p in packets if p['src_ip'] == fwd_ip and p['src_port'] == fwd_port]
    bwd_pkts = [p for p in packets if p['src_ip'] == bwd_ip and p['src_port'] == bwd_port]

    def stats(arr):
        if len(arr) == 0:
            return 0.0, 0.0, 0.0, 0.0
        return float(np.min(arr)), float(np.max(arr)), float(np.mean(arr)), float(np.std(arr))

    fwd_lens = np.array([p['len'] for p in fwd_pkts], dtype=float)
    bwd_lens = np.array([p['len'] for p in bwd_pkts], dtype=float)

    fwd_len_min, _, fwd_len_mean, fwd_packet_length_std = stats(fwd_lens)

# Compute forward URG flags
    fwd_urg_flags = sum(1 for p in fwd_pkts if p['flags'].get('URG', False))
    bwd_len_min, _, bwd_len_mean, _ = stats(bwd_lens)

    total_fwd_pkts, total_bwd_pkts = len(fwd_pkts), len(bwd_pkts)
    flow_bytes = float(np.sum(lengths))

    flow_iats = np.diff(times) if len(times) > 1 else np.array([0.0], dtype=float)
    flow_iats = np.nan_to_num(flow_iats, nan=0.0, posinf=0.0, neginf=0.0)
    flow_iats = [float(x) for x in flow_iats]  # ensure Python floats
    flow_iat_min = min(flow_iats) if flow_iats else 0.0

    def iats_stats(pkts):
        t = np.array([p['time'] for p in pkts])
        if len(t) <= 1:
            return 0.0, 0.0, 0.0, 0.0
        diffs = np.diff(t)
        return float(np.mean(diffs)), float(np.min(diffs)), float(np.max(diffs)), float(np.sum(diffs))

    fwd_iat_mean, fwd_iat_min, _, _ = iats_stats(fwd_pkts)
    bwd_iat_mean, bwd_iat_min, bwd_iat_max, bwd_iat_total = iats_stats(bwd_pkts)

    def py(val):
        if isinstance(val, (np.integer, np.int64)):
            return int(val)
        if isinstance(val, (np.floating, np.float64)):
            if np.isnan(val) or np.isinf(val):
                return 0.0
            return float(val)
        return val

    features = {
        "Protocol": py(protocol),
        "Fwd Packet Length Min": py(fwd_len_min),
        "Fwd Packet Length Std": py(fwd_packet_length_std),  # ✅ new  
        "Bwd Packet Length Min": py(bwd_len_min),
        "Flow Bytes/s": py(flow_bytes / flow_duration if flow_duration else 0.0),
        "Flow IAT Min": py(flow_iat_min),
        "Fwd IAT Mean": py(fwd_iat_mean),
        "Fwd IAT Min": py(fwd_iat_min),
        "Bwd IAT Total": py(bwd_iat_total),
        "Bwd IAT Max": py(bwd_iat_max),
        "Bwd IAT Min": py(bwd_iat_min),
        "Bwd PSH Flags": py(sum(1 for p in bwd_pkts if p['flags']['PSH'])),
        "Fwd URG Flags": py(fwd_urg_flags), 
        "Bwd URG Flags": py(sum(1 for p in bwd_pkts if p['flags']['URG'])),
        "Fwd Header Length": 40,
        "Bwd Header Length": 40,
        "Fwd Packets/s": py(total_fwd_pkts / flow_duration if flow_duration else 0.0),
        "Bwd Packets/s": py(total_bwd_pkts / flow_duration if flow_duration else 0.0),
        "Packet Length Min": py(np.min(lengths)),
        "Packet Length Variance": py(np.var(lengths)),
        "FIN Flag Count": py(sum(1 for p in packets if p['flags']['FIN'])),
        "SYN Flag Count": py(sum(1 for p in packets if p['flags']['SYN'])),
        "PSH Flag Count": py(sum(1 for p in packets if p['flags']['PSH'])),
        "ACK Flag Count": py(sum(1 for p in packets if p['flags']['ACK'])),
        "URG Flag Count": py(sum(1 for p in packets if p['flags']['URG'])),
        "CWE Flag Count": py(sum(1 for p in packets if p['flags']['CWR'])),
        "ECE Flag Count": py(sum(1 for p in packets if p['flags']['ECE'])),
        "Down/Up Ratio": py(total_bwd_pkts / total_fwd_pkts if total_fwd_pkts else 0.0),
        "Avg Fwd Segment Size": py(fwd_len_mean),
        "Avg Bwd Segment Size": py(bwd_len_mean),
        "Fwd Avg Bytes/Bulk": py(np.mean(fwd_lens) if total_fwd_pkts else 0.0),
        "Fwd Avg Packets/Bulk": py(total_fwd_pkts / flow_duration if flow_duration else 0.0),
        "Fwd Avg Bulk Rate": py((np.mean(fwd_lens) * total_fwd_pkts / flow_duration) if flow_duration else 0.0),
        "Bwd Avg Bytes/Bulk": py(np.mean(bwd_lens) if total_bwd_pkts else 0.0),
        "Bwd Avg Packets/Bulk": py(total_bwd_pkts / flow_duration if flow_duration else 0.0),
        "Bwd Avg Bulk Rate": py((np.mean(bwd_lens) * total_bwd_pkts / flow_duration) if flow_duration else 0.0),
        "Subflow Fwd Bytes": py(np.sum(fwd_lens)),
        "Subflow Bwd Bytes": py(np.sum(bwd_lens)),
        "Init Fwd Win Bytes": py(fwd_pkts[0]['window_size'] if total_fwd_pkts else 0),
        "Init Bwd Win Bytes": py(bwd_pkts[0]['window_size'] if total_bwd_pkts else 0),
        "Fwd Act Data Packets": py(sum(1 for p in fwd_pkts if p['tcp_len'] > 0)),
        "Fwd Seg Size Min": py(np.min([p['tcp_len'] for p in fwd_pkts]) if total_fwd_pkts else 0),
        "Active Std": py(np.std(flow_iats)),
        "Active Max": py(np.max(flow_iats)),
        "Active Min": py(np.min(flow_iats)),
        "Idle Std": 0.0,
        "Idle Min": 0.0,
    }

    return features

# ------------------- Capture Packets -------------------
def captures_packets(ssh):
    tshark_cmd = (
        "sudo tshark -i eth0 -T fields "
        "-e frame.time_relative -e ip.src -e ip.dst "
        "-e tcp.srcport -e tcp.dstport -e ip.proto "
        "-e frame.len -e tcp.flags -e tcp.window_size -e tcp.len "
        "-e ip.ttl -e tcp.analysis.retransmission "
        "-E separator=, -E aggregator=none -l"
    )
    stream = run_command_stream(ssh, tshark_cmd)

    for line in stream:
        if not monitoring_active:
            break
        if not line.strip():
            continue
        parts = line.strip().split(',')
        if len(parts) < 8:
            continue
        try:
            yield {
                'time': float(parts[0]),
                'src_ip': parts[1],
                'dst_ip': parts[2],
                'src_port': int(parts[3]) if parts[3] else 0,
                'dst_port': int(parts[4]) if parts[4] else 0,
                'proto': int(parts[5]) if parts[5] else 0,
                'len': float(parts[6]) if parts[6] else 0.0,
                'flags': parse_flags(parts[7] if parts[7] else '0x0'),
                'window_size': int(parts[8]) if len(parts) > 8 and parts[8] else 0,
                'tcp_len': float(parts[9]) if len(parts) > 9 and parts[9] else 0.0,
                'ip_ttl': int(parts[10]) if len(parts) > 10 and parts[10] else 0,
                'tcp_retrans': int(parts[11]) if len(parts) > 11 and parts[11] == '1' else 0
            }
        except Exception as e:
            print(f"[WARNING] Failed to parse line: {line.strip()} -> {e}")
            continue

# ------------------- Monitoring Loop -------------------
def monitoring_loop(user):
    global monitoring_active
    flows = {}

    try:
        for packet in captures_packets(ssh_client):
            if not monitoring_active:
                break

            flow_key = add_packet_to_flow(flows, packet)
            features = compute_flow_features(flows[flow_key])

            # Ordered feature list for model
            def safe_float(x):
                if x is None:
                    return 0.0
                try:
                    # Convert NumPy types to Python float, round to 6 decimals
                    return float(np.round(float(x), 6))
                except:
                    return 0.0

            # Usage in monitoring_loop
            feature_list = [safe_float(features.get(key, 0.0)) for key in FEATURE_ORDER]

            # Skip empty/all-zero feature sets
            if all(x == 0.0 for x in feature_list):
                continue

            prediction = 'safe'
            try:
                response = requests.post(MODEL_URL, json={"features": feature_list})
                if response.status_code == 200:
                    data = response.json()
                    pred_value = data.get("prediction", 0)  # this is numeric 0-6

                    # Map numeric prediction to label
                    prediction_map = {
                        0: "safe",
                        1: "Botnet",
                        2: "Bruteforce",
                        3: "DDoS",
                        4: "Infiltration",
                        5: "DoS",
                        6: "Portscan",
                    }

                    prediction = prediction_map.get(pred_value, "safe")
                else:
                    prediction = "safe"
            except Exception as e:
                print(f"Prediction failed: {e}")
                prediction = "safe"

            db_features = {FEATURE_KEY_MAP[k]: v for k, v in features.items() if k in FEATURE_KEY_MAP}

            try:
                Packets.objects.create(
                    user=user,
                    flow_key=str(flow_key),
                    prediction=prediction,
                    src_ip=packet['src_ip'],
                    dst_ip=packet['dst_ip'],
                    **db_features
                )
            except Exception as e:
                print(f"[ERROR] Failed to save packet to DB: {e}")
    except (paramiko.SSHException, ConnectionResetError) as e:
        print(f"[ERROR] SSH connection lost: {e}")
        disconnect_ssh()

# ------------------- Public Control -------------------
def start_monitoring(user):
    global monitoring_active, monitor_thread, ssh_client
    ssh_client = setup_ssh()
    if not ssh_client:
        print("[ERROR] Cannot start monitoring, SSH connection failed.")
        return
    monitoring_active = True
    monitor_thread = threading.Thread(target=monitoring_loop, args=(user,))
    monitor_thread.start()

def pause_monitoring(user):
    global monitoring_active, ssh_client
    monitoring_active = False
    if ssh_client:
        try:
            print("[DEBUG] Pausing tshark...")
            ssh_client.exec_command("sudo pkill -f tshark")
        except Exception as e:
            print(f"[ERROR] Failed to pause tshark: {e}")

def disconnect_ssh():
    global monitoring_active, ssh_client
    monitoring_active = False
    if ssh_client:
        try:
            print("[DEBUG] Killing remote tshark processes...")
            stdin, stdout, stderr = ssh_client.exec_command("sudo pkill -f tshark")
            stdout.channel.recv_exit_status()  # Wait for command to complete
            print("[DEBUG] tshark processes killed.")
        except Exception as e:
            print(f"[ERROR] Failed to kill tshark: {e}")
        ssh_client.close()
        ssh_client = None

def continue_monitoring(user):
    """
    Resume monitoring after it was paused.
    Does not reconnect SSH if it's already connected.
    """
    global monitoring_active, monitor_thread, ssh_client
    if monitoring_active:
        print("[INFO] Monitoring is already active.")
        return

    if not ssh_client:
        ssh_client = setup_ssh()
        if not ssh_client:
            print("[ERROR] Cannot continue monitoring, SSH connection failed.")
            return

    monitoring_active = True
    monitor_thread = threading.Thread(target=monitoring_loop, args=(user, ))
    monitor_thread.start()
    print("[INFO] Monitoring resumed.")
