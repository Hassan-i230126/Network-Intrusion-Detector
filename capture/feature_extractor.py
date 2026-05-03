"""
feature_extractor.py — Extract KDD-compatible features from network flows.

Given a completed flow (list of scapy packets or a simulated record),
extracts the same 41 features that the preprocessor expects.
"""

import os
import collections
from typing import Dict, List, Optional, Any
from datetime import datetime

import numpy as np
import joblib

# Port-to-service mapping covering the 70 NSL-KDD services
PORT_TO_SERVICE: Dict[int, str] = {
    7: 'echo', 9: 'discard', 11: 'systat', 13: 'daytime',
    15: 'netstat', 20: 'ftp_data', 21: 'ftp', 22: 'ssh',
    23: 'telnet', 25: 'smtp', 37: 'time', 42: 'name',
    43: 'whois', 53: 'domain', 57: 'mtp', 70: 'gopher',
    79: 'finger', 80: 'http', 87: 'link', 95: 'supdup',
    101: 'hostnames', 102: 'iso_tsap', 105: 'csnet_ns',
    109: 'pop_2', 110: 'pop_3', 111: 'sunrpc', 113: 'auth',
    115: 'sftp', 117: 'uucp_path', 119: 'nntp', 123: 'ntp_u',
    135: 'netbios_ns', 137: 'netbios_ns', 138: 'netbios_dgm',
    139: 'netbios_ssn', 143: 'imap4', 161: 'private',
    179: 'bgp', 194: 'IRC', 210: 'Z39_50',
    220: 'imap4', 389: 'ldap', 443: 'http_443',
    512: 'exec', 513: 'login', 514: 'shell',
    515: 'printer', 520: 'efs', 530: 'courier',
    540: 'uucp', 543: 'klogin', 544: 'kshell',
    636: 'ldap', 749: 'kerberos', 993: 'imap4',
    995: 'pop_3', 1433: 'sql_net', 1521: 'sql_net',
    1080: 'other', 3306: 'sql_net', 5432: 'sql_net',
    8080: 'http', 8443: 'http_443',
    1109: 'pop_2', 1110: 'pop_3', 2049: 'other',
    2121: 'ftp', 3000: 'http', 5000: 'http',
    5900: 'private', 6000: 'X11', 6667: 'IRC',
    8000: 'http', 8888: 'http', 9090: 'http',
}

# TCP flag to KDD flag mapping
TCP_FLAG_MAP: Dict[str, str] = {
    'SYN': 'S0',        # SYN sent, no response
    'SYN-ACK': 'S1',    # SYN-ACK received
    'FIN': 'SF',         # Normal finish
    'RST': 'REJ',        # Connection rejected
    'RST-ACK': 'RSTO',   # Reset by originator
    'FIN-ACK': 'SF',     # Normal close
}

# Sliding window for traffic features
_flow_history: collections.deque = collections.deque(maxlen=100)


def get_service_from_port(port: int) -> str:
    """Map a destination port to a KDD service name."""
    return PORT_TO_SERVICE.get(port, 'other')


def derive_flag_from_tcp(flags: List[str]) -> str:
    """Derive a KDD flag value from observed TCP flags."""
    flag_set = set(flags)
    if 'RST' in flag_set:
        if 'SYN' in flag_set and 'ACK' not in flag_set:
            return 'RSTOS0'
        elif 'ACK' in flag_set:
            return 'RSTO'
        return 'REJ'
    elif 'FIN' in flag_set:
        return 'SF'
    elif 'SYN' in flag_set and 'ACK' in flag_set:
        return 'S1'
    elif 'SYN' in flag_set:
        return 'S0'
    elif 'ACK' in flag_set:
        return 'S2'
    return 'OTH'


def compute_traffic_features(flow_record: Dict) -> Dict[str, float]:
    """Compute traffic features from the sliding window of recent flows."""
    _flow_history.append(flow_record)
    history = list(_flow_history)

    dst_ip = flow_record.get('dst_ip', '')
    service = flow_record.get('service', 'other')
    src_port = flow_record.get('src_port', 0)

    # count: connections to same host in last 2 seconds (approximated by window)
    same_host = [f for f in history if f.get('dst_ip') == dst_ip]
    count = len(same_host)

    # srv_count: connections to same service
    same_srv = [f for f in same_host if f.get('service') == service]
    srv_count = len(same_srv)

    # Error rates
    serror = sum(1 for f in same_host if f.get('flag', '') in ['S0', 'S1', 'S2', 'S3'])
    rerror = sum(1 for f in same_host if f.get('flag', '') in ['REJ'])

    serror_rate = serror / count if count > 0 else 0.0
    srv_serror_rate = sum(1 for f in same_srv if f.get('flag', '') in ['S0', 'S1', 'S2', 'S3']) / srv_count if srv_count > 0 else 0.0
    rerror_rate = rerror / count if count > 0 else 0.0
    srv_rerror_rate = sum(1 for f in same_srv if f.get('flag', '') in ['REJ']) / srv_count if srv_count > 0 else 0.0

    # Same/diff service rates
    same_srv_rate = len(same_srv) / count if count > 0 else 0.0
    diff_services = len(set(f.get('service', '') for f in same_host))
    diff_srv_rate = (diff_services - 1) / count if count > 1 else 0.0

    # srv_diff_host_rate
    srv_hosts = set(f.get('dst_ip', '') for f in same_srv)
    srv_diff_host_rate = (len(srv_hosts) - 1) / srv_count if srv_count > 1 else 0.0

    # dst_host features (last 100 connections)
    dst_host_same = [f for f in history if f.get('dst_ip') == dst_ip]
    dst_host_count = len(dst_host_same)

    dst_host_srv_same = [f for f in dst_host_same if f.get('service') == service]
    dst_host_srv_count = len(dst_host_srv_same)

    dst_host_same_srv_rate = dst_host_srv_count / dst_host_count if dst_host_count > 0 else 0.0

    dst_host_diff_services = len(set(f.get('service', '') for f in dst_host_same))
    dst_host_diff_srv_rate = (dst_host_diff_services - 1) / dst_host_count if dst_host_count > 1 else 0.0

    dst_host_same_src_port = sum(1 for f in dst_host_same if f.get('src_port') == src_port)
    dst_host_same_src_port_rate = dst_host_same_src_port / dst_host_count if dst_host_count > 0 else 0.0

    dst_host_srv_hosts = set(f.get('src_ip', '') for f in dst_host_srv_same)
    dst_host_srv_diff_host_rate = (len(dst_host_srv_hosts) - 1) / dst_host_srv_count if dst_host_srv_count > 1 else 0.0

    dst_host_serror = sum(1 for f in dst_host_same if f.get('flag', '') in ['S0', 'S1', 'S2', 'S3'])
    dst_host_serror_rate = dst_host_serror / dst_host_count if dst_host_count > 0 else 0.0

    dst_host_srv_serror = sum(1 for f in dst_host_srv_same if f.get('flag', '') in ['S0', 'S1', 'S2', 'S3'])
    dst_host_srv_serror_rate = dst_host_srv_serror / dst_host_srv_count if dst_host_srv_count > 0 else 0.0

    dst_host_rerror = sum(1 for f in dst_host_same if f.get('flag', '') in ['REJ'])
    dst_host_rerror_rate = dst_host_rerror / dst_host_count if dst_host_count > 0 else 0.0

    dst_host_srv_rerror = sum(1 for f in dst_host_srv_same if f.get('flag', '') in ['REJ'])
    dst_host_srv_rerror_rate = dst_host_srv_rerror / dst_host_srv_count if dst_host_srv_count > 0 else 0.0

    return {
        'count': count,
        'srv_count': srv_count,
        'serror_rate': round(serror_rate, 2),
        'srv_serror_rate': round(srv_serror_rate, 2),
        'rerror_rate': round(rerror_rate, 2),
        'srv_rerror_rate': round(srv_rerror_rate, 2),
        'same_srv_rate': round(same_srv_rate, 2),
        'diff_srv_rate': round(diff_srv_rate, 2),
        'srv_diff_host_rate': round(srv_diff_host_rate, 2),
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_srv_rate': round(dst_host_same_srv_rate, 2),
        'dst_host_diff_srv_rate': round(dst_host_diff_srv_rate, 2),
        'dst_host_same_src_port_rate': round(dst_host_same_src_port_rate, 2),
        'dst_host_srv_diff_host_rate': round(dst_host_srv_diff_host_rate, 2),
        'dst_host_serror_rate': round(dst_host_serror_rate, 2),
        'dst_host_srv_serror_rate': round(dst_host_srv_serror_rate, 2),
        'dst_host_rerror_rate': round(dst_host_rerror_rate, 2),
        'dst_host_srv_rerror_rate': round(dst_host_srv_rerror_rate, 2),
    }


def extract_features_from_packets(packets: List[Any], flow_meta: Dict) -> Optional[Dict]:
    """Extract 41 KDD features from a list of scapy packets."""
    try:
        if not packets:
            return None

        first_pkt = packets[0]
        last_pkt = packets[-1]

        # Basic features
        duration = float(last_pkt.time - first_pkt.time) if len(packets) > 1 else 0.0

        protocol = flow_meta.get('protocol', 'tcp')
        dst_port = flow_meta.get('dst_port', 80)
        service = get_service_from_port(dst_port)

        # Byte counts
        src_bytes = sum(len(p) for p in packets if hasattr(p, 'src') and p.src == flow_meta.get('src_ip'))
        dst_bytes = sum(len(p) for p in packets if hasattr(p, 'src') and p.src == flow_meta.get('dst_ip'))

        # TCP flags
        tcp_flags = []
        urgent_count = 0
        wrong_fragment = 0

        for p in packets:
            if hasattr(p, 'haslayer'):
                try:
                    from scapy.all import TCP, IP
                    if p.haslayer(TCP):
                        flags = str(p[TCP].flags)
                        tcp_flags.append(flags)
                        if 'U' in flags:
                            urgent_count += 1
                    if p.haslayer(IP):
                        if p[IP].frag > 0:
                            wrong_fragment += 1
                except Exception:
                    pass

        flag = derive_flag_from_tcp(tcp_flags) if tcp_flags else 'SF'

        # Land attack check
        src_ip = flow_meta.get('src_ip', '')
        dst_ip = flow_meta.get('dst_ip', '')
        src_port = flow_meta.get('src_port', 0)
        land = 1 if src_ip == dst_ip and src_port == dst_port else 0

        # Build the feature dict
        features = {
            'duration': duration,
            'protocol_type': protocol,
            'service': service,
            'flag': flag,
            'src_bytes': src_bytes,
            'dst_bytes': dst_bytes,
            'land': land,
            'wrong_fragment': wrong_fragment,
            'urgent': urgent_count,
            # Content features (defaults — require deep inspection)
            'hot': 0, 'num_failed_logins': 0, 'logged_in': 0,
            'num_compromised': 0, 'root_shell': 0, 'su_attempted': 0,
            'num_root': 0, 'num_file_creations': 0, 'num_shells': 0,
            'num_access_files': 0, 'num_outbound_cmds': 0,
            'is_host_login': 0, 'is_guest_login': 0,
        }

        # Traffic features from sliding window
        flow_record = {
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'src_port': src_port, 'dst_port': dst_port,
            'service': service, 'flag': flag, 'protocol': protocol,
        }
        traffic = compute_traffic_features(flow_record)
        features.update(traffic)

        return features

    except Exception:
        return None


def features_to_array(features: Dict, preprocessor_path: str = 'models/preprocessor.pkl') -> Optional[np.ndarray]:
    """Transform a feature dict into a model-ready numpy array."""
    try:
        import pandas as pd
        from pipeline.preprocessor import add_engineered_features, CATEGORICAL_FEATURES

        preprocessor = joblib.load(preprocessor_path)

        # Build a single-row DataFrame
        df = pd.DataFrame([features])
        df_eng = add_engineered_features(df)

        numerical_features = [
            f for f in df_eng.columns
            if f not in CATEGORICAL_FEATURES
        ]
        X = df_eng[CATEGORICAL_FEATURES + numerical_features]

        return preprocessor.transform(X)
    except Exception:
        return None
