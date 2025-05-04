import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import json

high_severity_levels = {
    # System logs
    41: "Unexpected shutdown/restart",
    55: "File system corruption",
    1014: "DNS resolution issues",
    1001: "System crash (blue screen)",
    2004: "Low system resources",
    9: "Disk controller error",
    11: "Disk I/O errors",
    37: "CPU power issues",
    50: "Disk warning",
    27: "Driver detected a critical issue",
    247: "Critical driver error",
    7034: "Service terminated unexpectedly",
    6008: "Unexpected shutdown",
    7023: "Service terminated with error",
    1008: "Performance counter issues",

    # Application logs
    1000: "Application crash",
    1026: ".NET unhandled exception",
    11724: "Installation issues",
    1002: "Application unresponsive",
    1500: "User profile load error",
    8193: "Shadow copy failed",
    1030: "Group Policy error",
    11707: "Installation critical error",
    5000: "Unhandled app exception",
    3005: "Web app (IIS) error",

    # Security logs
    4625: "Failed login attempt",
    4688: "Suspicious process execution",
    4720: "Unauthorized user creation",
    4726: "User deletion",
    4740: "Account lockout",
    4768: "Authentication issue",
    4624: "Suspicious successful login",
    4634: "Account logoff",
    4648: "Credential misuse",
    4670: "Sensitive permissions change",
    4672:"Special privileges assigned to new logon",
    4697: "Potential malicious service",
    4798: "Sensitive group enumeration",
    5140: "Unauthorized file share access",
    1102: "Audit log cleared",
    4907: "Auditing settings changed",
    4776: "Failed NTLM authentication"
}

Error_logs = {
        7023: "Service terminated with error",
        1008: "Performance counter issues",
        1026: ".NET unhandled exception",
        11724: "Installation issues",
        1002: "Application unresponsive",
        8193: "Shadow copy failed",
        1030: "Group Policy error",
        11707: "Installation critical error",
        5000: "Unhandled app exception",
        7024: "Service failed to start",
        4627: "Authentication package error",
        4703: "Rights assigned error",
        3: "Critical system hardware error",
        5722: "Trust relationship failure",
        3001: "Disk quota exceeded",
        7011: "Service timeout error",
         165: "RAID controller failure",
        7026: "Driver failed to load",
        4004: "DNS server failure",
        -2147477639: "Fatal hardware error reported by firmware",
        -2147477643: "Hardware error detected by the platform",
    }

Informative_logs = {
        4624: "Successful login",
        4634: "Account logoff",
        5140: "File share accessed",
        3005: "Web app (IIS) event",
        1030: "Policy applied successfully",
        1014: "DNS resolution completed",
        4000: "DNS query completed",
        4688: "New process creation",
        1: "System startup",
        2: "System shutdown",
        129: "Disk operation timeout",
        156: "Power issue detected with hardware",
        4902: "Audit policy change",
        7040: "Service status changed",
        6005: "System startup",
        6013: "System uptime reported",
        12: "System boot started",
        25: "Unexpected system restart or shutdown",
        153: "Disk operation retries exceeded threshold",
        4700: "Group membership change"
    }

Other_logs = {
        50: "Disk warning",
        37: "CPU power issues",
        1500: "User profile load error",
        4798: "Sensitive group enumeration",
        4648: "Credential misuse",
        4726: "User deletion",
        4768: "Authentication issue",
        7035: "Service control operation",
        7036: "Service state change",
        10016: "Distributed COM warning",
        5011: "Cluster resource offline",
        1530: "Profile unload issue",
        6009: "OS version reported",
        6011: "Timezone change",
        26: "Memory warning detected",
        32: "Driver failed to initialize",
        20: "Disk controller issue detected",
        238: "Resource conflict detected",
       
        5379: "Failed authentication request",
        5058: "Cryptographic key operation failure",
        5059: "Application pool terminated",
        5061: "Cryptographic operation failed",
        -1073741724: "Process terminated unexpectedly with NTSTATUS error"
    }

critical_levels = [1,2,3]

def detect_threats(log_entry, high_severity_levels):
    threats = []
    event_id = log_entry.get("EventID")

    if event_id in high_severity_levels:
        threats.append(high_severity_levels[event_id])
        
    return threats

def detect_anomalies(event_counts):
    event_frequencies = np.array(list(event_counts.values()))
    if len(event_frequencies) == 0:
        return {}
    threshold = np.mean(event_frequencies) + 2 * np.std(event_frequencies)
    return {event_id: "High event occurrence anomaly" for event_id, count in event_counts.items() if count > threshold}

def ml_anomaly_detection(log_data):
    if not log_data:
        return {}
    
    preprocessed_data = []
    for log in log_data:
        flattened_log = {key: (",".join(value) if isinstance(value, list) else value) for key, value in log.items()}
        preprocessed_data.append(flattened_log)
        
    df = pd.DataFrame(preprocessed_data)

    model = IsolationForest(contamination=0.01, random_state=42)
    log_features = pd.get_dummies(df, drop_first=True)
    model.fit(log_features)
    predictions = model.predict(log_features)
    return {str(log_data[i]["EventID"]): "ML-detected anomaly" for i, pred in enumerate(predictions) if pred == -1}

# def process_logs_in_batches(logs, batch_size=15):
#     blockchain_logs, mongodb_logs, event_counts = [], [], {}
#     for i in range(0, len(logs), batch_size):
#         batch = logs[i:i + batch_size]
#         for log_entry in batch:
#             log_entry["threats"] = detect_threats(log_entry, high_severity_levels)
#             event_counts[log_entry["EventID"]] = event_counts.get(log_entry["EventID"], 0) + 1

#             if log_entry["Level"] in critical_levels or log_entry["threats"]:
#                 blockchain_logs.append(log_entry)
#             else:
#                 mongodb_logs.append(log_entry)
#         anomalies = detect_anomalies(event_counts)
#         ml_anomalies = ml_anomaly_detection(batch)

#         for log in mongodb_logs[:]:
#             if log["EventID"] in anomalies or log["EventID"] in ml_anomalies:
#                 log["anomaly"] = anomalies.get(log["EventID"], ml_anomalies.get(log["EventID"]))
                
#                 if log["Level"] in critical_levels or log["threats"]:
#                     mongodb_logs.remove(log)
#                     blockchain_logs.append(log)
                
#                 log["threats"].append(log["anomaly"])  # Move anomalies to threats

#         for log in blockchain_logs:
#             if log["EventID"] in anomalies or log["EventID"] in ml_anomalies:
#                 log["anomaly"] = anomalies.get(log["EventID"]), ml_anomalies.get(log["EventID"])
#                 # log["threats"].append(log["anomaly"])  # Move anomalies to threats
                
#     return blockchain_logs, mongodb_logs

def process_logs_in_batches(logs, batch_size=15):
    blockchain_logs, mongodb_logs, event_counts = [], [], {}

    for i in range(0, len(logs), batch_size):
        batch = logs[i:i + batch_size]
        for log_entry in batch:
            log_entry["threats"] = detect_threats(log_entry, high_severity_levels)
            event_counts[log_entry["EventID"]] = event_counts.get(log_entry["EventID"], 0) + 1

            if log_entry["Level"] in critical_levels or log_entry["threats"]:
                blockchain_logs.append(log_entry)
            else:
                mongodb_logs.append(log_entry)

        anomalies = detect_anomalies(event_counts)
        ml_anomalies = ml_anomaly_detection(batch)

        for log in mongodb_logs[:]:
            anomaly_reasons = []

            if log["EventID"] in anomalies:
                anomaly_reasons.append(anomalies[log["EventID"]])
            if log["EventID"] in ml_anomalies:
                anomaly_reasons.append(ml_anomalies[log["EventID"]])

            # Append anomaly reasons into threats (avoid duplicates)
            for reason in anomaly_reasons:
                if reason and reason not in log["threats"]:
                    log["threats"].append(reason)

            # If threats became non-empty or level is critical, move to blockchain
            if log["Level"] in critical_levels or log["threats"]:
                mongodb_logs.remove(log)
                blockchain_logs.append(log)

        for log in blockchain_logs:
            anomaly_reasons = []

            if log["EventID"] in anomalies:
                anomaly_reasons.append(anomalies[log["EventID"]])
            if log["EventID"] in ml_anomalies:
                anomaly_reasons.append(ml_anomalies[log["EventID"]])

            for reason in anomaly_reasons:
                if reason and reason not in log["threats"]:
                    log["threats"].append(reason)

    return blockchain_logs, mongodb_logs
