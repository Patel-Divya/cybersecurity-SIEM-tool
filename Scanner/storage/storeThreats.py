from config.mongo_confing import collections
import hashlib
import json

def storeThreat(log_id, threats, category, type):

    if not log_id:
        raise ValueError("storeThreats.py - line 8: Log_id must be present")
    
    if not threats:
        raise ValueError("storeThreats.py - line 8: threats must be present")
    
    threat_log = {
        'category': category,
        'type': type,
        "log_id": log_id,
        "threat": threats
    }

    
    collections['threats_alerts'].insert_one(threat_log)