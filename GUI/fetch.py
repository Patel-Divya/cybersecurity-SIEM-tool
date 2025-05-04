from flask import jsonify
from mongo_confing import collections
import hashlib
import json
from bson import ObjectId

critical_levels = [1,2,3]
informative_level = 4

def verify_logs(logs, type):
    verified_logs = []
    
    for log in logs:
        if "hash" not in log:
            log["verified"] = False
            log["modified"] = True  # If no hash, treat as modified
            verified_logs.append(log)
            print('Verify failed')
            continue  

        log_hash = log["hash"]
        
        # Recalculate hash from log data (excluding hash field itself)
        block = {
                "eventID": log["EventID"],
                "time": log["TimeCreated"],
                "threats": log["threats"],
                "previous_hash": log['previous_hash'],  
            }
        
        recalculated_hash = hashlib.sha256(json.dumps(block, sort_keys=True).encode()).hexdigest()

        # Fetch stored hash from hashes_collection
        stored_hash_entry = collections[f"{type}_blockchain_hashes"].find_one({"hash": log_hash})

        # print(stored_hash_entry["hash"], '-', log_hash)
        # Check integrity
        log["verified"] = stored_hash_entry and stored_hash_entry["hash"] == recalculated_hash
        log["modified"] = not log["verified"]  # If verification fails, mark as modified

        # print('\n',stored_hash_entry["hash"],'-',recalculated_hash)
        # print('verified:',log["verified"],'modified:',log["modified"], 'correct:', (stored_hash_entry["hash"] == recalculated_hash))
        clean_log = {
            'Category': type,
            'EventID': log['EventID'],
            'Message': log['Message'],
            'TimeCreated': log['TimeCreated'],
            'Level': log['Level'],
            'modified': log['modified']
        }
        verified_logs.append(clean_log)
        # print('Verify passed:',log['modified'])

    return verified_logs

def fetch_logs_by_level(log_type, level):
    if log_type == 'all':
        systemLogs = fetch_logs_by_level('system',level)
        applicationLogs = fetch_logs_by_level('application', level)
        securityLogs = fetch_logs_by_level('security', level)

        for log in systemLogs:
            log['category'] = 'system'
        for log in applicationLogs:
            log['category'] = 'application'
        for log in securityLogs:
            log['category'] = 'security'

        return securityLogs + systemLogs + applicationLogs
    
    else:
        if log_type not in ["system", "application", "security"]:
            raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

        if level == 'critical':
            collection_name = f"{log_type}_critical_logs"
            logs = list(collections[collection_name].find({"Level": {"$in": [1, 3]}}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1, 'threats':1, 'previous_hash':1, 'hash':1}))
            return verify_logs(logs, log_type)
    
        elif level == 'error':
            collection_name = f"{log_type}_critical_logs"
            logs = list(collections[collection_name].find({"Level": 2}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1, 'threats':1, 'previous_hash':1, 'hash':1}))
            return verify_logs(logs, log_type)
    
        elif level == 'informative':
            collection_name = f"{log_type}_other_logs"
            logs = list(collections[collection_name].find({"Level": 4}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1}))

            for log in logs:
                log['Category'] = log_type

            return logs
    
        elif level == 'others':
            collection_name = f"{log_type}_other_logs"
            logs = list(collections[collection_name].find({"Level": {"$ne": 4}}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1}))
            
            for log in logs:
                log['Category'] = log_type

            return logs
    
        else:
            collection_name = f"{log_type}_other_logs"
            logs = list(collections[collection_name].find({"Level": level}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1}))
            
            for log in logs:
                log['Category'] = log_type
                
            return logs

def count_logs(log_type):
    if log_type == "all":
        system = count_logs('system')
        application = count_logs('application')
        security = count_logs('security')


        return {
            "critical": system['critical'] + application['critical'] + security['critical'],
            "error": system['error'] + application['error'] + security['error'],
            "informative": system['informative'] + application['informative'] + security['informative'],
            "others": system['others'] + application['others'] + security['others']
        }
    
    else:
        if log_type not in ["system", "application", "security"]:
            raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

        critical_collection = f"{log_type}_critical_logs"
        other_collection = f"{log_type}_other_logs"

        return {
            "critical": collections[critical_collection].count_documents({"Level": {"$in": [1, 3]}}),
            "error": collections[critical_collection].count_documents({"Level": 2}),
            "informative": collections[other_collection].count_documents({"Level": 4}),
            "others": collections[other_collection].count_documents({"Level": {"$nin": [4]}})
        }

def update_resolved_count(type, level):
    if type not in ["system", "application", "security"]:
        raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

    # Find existing document
    query = {"type": type, "level": level}
    update = {"$inc": {"count": 1}}  # Increment count by 1

    # Update existing document or insert if not found
    collections["resolved_log_count"].update_one(query, update, upsert=True)
    return

def get_resolved_count(type, level):
    if type == 'all':
        system = get_resolved_count('system', level).get_json()
        application = get_resolved_count('application', level).get_json()
        security = get_resolved_count('security', level).get_json()

        return jsonify(system + application + security)

    
    if type not in ["system", "application", "security"]:
        return jsonify(0)
        # raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")
    
    count = 0

    if level == 'critical':
        query = {"type": type, "level": {"$in": [1, 3]}}
        result = collections["resolved_log_count"].find_one(query, {"_id": 0, "count": 1})
        
        if result: 
            count = result['count']
            result = collections["resolved_log_count"].find_one(query, {"_id": 0, "count": 1})
            if result: 
                count += result['count']

    elif level == 'error':
        query = {"type": type, "level": 2}
        result = collections["resolved_log_count"].find_one(query, {"_id": 0, "count": 1})
        if result: 
            count = result['count']
        
    elif level == 'informative':
        query = {"type": type, "level": 4}
        result = collections["resolved_log_count"].find_one(query, {"_id": 0, "count": 1})
        if result: 
            count = result['count']
        
    elif level == 'others':
        query = {"type": type, "level": {"$ne": 4}}
        result = collections["resolved_log_count"].find_one(query, {"_id": 0, "count": 1})
        if result: 
            count = result['count']

    else:
        print("None")
        return jsonify(0)
        
    return jsonify(count)  # Return count if exists, otherwise 0

def get_total_resolved_count(log_type):
    if log_type not in ["system", "application", "security"]:
        raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

    pipeline = [
        {"$match": {"type": log_type}},
        {"$group": {"_id": None, "total_count": {"$sum": "$count"}}}
    ]

    result = list(collections["resolved_log_count"].aggregate(pipeline))
    
    return result[0]["total_count"] if result else 0

def get_all_resolved_count():
    pipeline = [
        {"$group": {"_id": None, "total_count": {"$sum": "$count"}}}
    ]

    result = list(collections["resolved_log_count"].aggregate(pipeline))
    
    return result[0]["total_count"] if result else 0

def getLog(category, level, eventID, time):
    try:
        collection_name = f"{category}_critical_logs" if level in [1, 3, 2] else f"{category}_other_logs"
        log =  collections[collection_name].find_one({
            "EventID": eventID,
            "TimeCreated": time,
            "Level": level
            }, {"_id": 0})
        
        # print(eventID, level, category, time, collection_name)
        # print(f"{category}_critical_logs" if level in [1, 3, 2] else f"{category}_other_logs")

        if log:
            return jsonify(log)
        else:
            return jsonify({"error": "Log not found"}), 404
    
    except Exception as e:
        print("[getLog error]:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

def delete_log(eventID, timeStamp, level, type, fromAudit = False):
    if not eventID or not timeStamp or not level:
        return False

    if not fromAudit:
        if level in critical_levels:
            log = collections[f"{type}_critical_logs"].find_one({"EventID": eventID, "TimeCreated": timeStamp, "Level":level})
            if not log:
                return False
            if "hash" not in log:
                raise ValueError("Log must contain a 'hash' key")

            hash_value = log["hash"]

            # Step 1: Delete the log first
            log_deleted = collections[f"{type}_critical_logs"].delete_one({"hash": hash_value})

            if log_deleted.deleted_count == 1:
                # Step 2: Now delete the hash since no log references it
                hash_deleted = collections[f"{type}_blockchain_hashes"].delete_one({"hash": hash_value})

                if hash_deleted.deleted_count == 1:
                    print(f"Log with hash {hash_value} and its reference deleted successfully.")
                    # update_resolved_count(type, level)
                    return True
                else:
                    print(f"Log deleted, but hash {hash_value} was not found in hashes_collection.")
                    return False
            else:
                print(f"Log with hash {hash_value} not found, deletion failed.")
                return False

        else:
            log_deleted = collections[f"{type}_other_logs"].delete_one({"EventID": eventID, "TimeCreated": timeStamp, "Level":level})
            if log_deleted.deleted_count == 1:
                # if level == 4:
                #     # update_resolved_count(type, level)
                # else:
                #     # update_resolved_count(type, "other")
                return True
            else:
                return False
    else:
        log = collections["marked_as_review"].find_one({"EventID": eventID, "TimeCreated": timeStamp, "Level":level, "Category":type})
        if not log:
            print('Log not found in marked_as_review collection')
            return False
        
        log_deleted = collections["marked_as_review"].delete_one({"EventID": eventID, "TimeCreated": timeStamp, "Level":level, "Category":type})
        if log_deleted.deleted_count == 1:
            update_resolved_count(type, level)
            return True
        else:
            print('Log not found in marked_as_review collection')
            return False
        
def markAsReview(category, level, eventID, time):
    try:
        print(type(category), type(level), type(eventID), type(time))
        collection_name = f"{category}_critical_logs" if level in [1, 3, 2] else f"{category}_other_logs"

        if category not in ["system", "application", "security"]:
            raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

        # Fetch the log from the appropriate collection
        log = collections[collection_name].find_one({"EventID": eventID, "TimeCreated": time, "Level": level})

        if not log:
            return False

        # Prepare logDetails based on whether it is a critical log
        logDetails = {
            'LogID': log['_id'],
            "Category": category,
            "EventID": eventID,
            "Level": level,
            'TimeCreated': time,
            'Source': log.get('Source'),
            'Task': log.get('Task'),
            'Computer': log.get('Computer'),
            'Message': log.get('Message'),
            'threats': log.get('threats'),
        }

        if level in critical_levels:
            log_verified = verify_logs([log], category)[0]
            if not log_verified:
                return False
            logDetails['modified'] = log_verified.get('modified')

        # Insert into the marked_as_review collection
        result = collections['marked_as_review'].insert_one(logDetails)
        return result.acknowledged

    except Exception as e:
        print("[markAsReview error]:", e)
        return False

def viewMarkedAsReview(category, level, eventID, time):
    try:
        collection_name = "marked_as_review"
        log =  collections[collection_name].find_one({
            "EventID": eventID,
            'Category': category,
            "TimeCreated": time,
            "Level": level
            }, {"_id": 0, "LogID":0})
                
        if log:
            return jsonify(log)
        else:
            return jsonify({"error": "Log not found"}), 404
    
    except Exception as e:
        print("[getLog error]:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

def countMarkedAsReview(category):
    collection_name = "marked_as_review"

    if category == "all":
        system = countMarkedAsReview('system')
        application = countMarkedAsReview('application')
        security = countMarkedAsReview('security')

        return {
            "critical": system['critical'] + application['critical'] + security['critical'],
            "error": system['error'] + application['error'] + security['error'],
            "informative": system['informative'] + application['informative'] + security['informative'],
            "others": system['others'] + application['others'] + security['others']
        }
    
    else:
        if category not in ["system", "application", "security"]:
            raise ValueError("Invalid log type. Must be 'system', 'application', or 'security'.")

        return {
            "critical": collections[collection_name].count_documents({"Level": {"$in": [1, 3]}, "Category":category}),
            "error": collections[collection_name].count_documents({"Level": 2, "Category":category}),
            "informative": collections[collection_name].count_documents({"Level": 4, "Category":category}),
            "others": collections[collection_name].count_documents({"Level": {"$nin": [4]}, "Category":category})
        }

def allMarkedAsReview():
    try:
        collection_name = "marked_as_review"
        logs = list(collections[collection_name].find({}, {"_id": 0, 'EventID':1, 'Level':1, 'TimeCreated':1, 'Message':1, 'Category':1, 'modified':1}))
        print(logs)
        return logs
    except Exception as e:
        print("[getLog error]:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

def get_threat_stats():
    resolved_count = get_all_resolved_count()
    threat_alerts_count = collections["threats_alerts"].count_documents({})
    mark_for_review_count = collections["marked_as_review"].count_documents({})
    total_threats = resolved_count + threat_alerts_count + mark_for_review_count

    return {
        "resolved_threats": resolved_count,
        "total_threats": total_threats,
        "threat_alerts_count": threat_alerts_count
    }

def getThreats():
    try:
        cursor = collections["threats_alerts"].find({}, {
            "category": 1,
            "type": 1,
            "log_id": 1,
            "threat": 1,
            "_id": 0
        })

        result = []
        for doc in cursor:
            result.append({
                "category": doc.get("category"),
                "type": doc.get("type"),
                "log_id": str(doc.get("log_id")),
                "threats": doc.get("threat", [])
            })

        return result

    except Exception as e:
        print(f"Error fetching threat data: {e}")
        return []
    
def view_threat(category, type, id):
    try:
        collection_name = f"{category}_critical_logs" if type == "critical" else f"{category}_other_logs"
        print(collection_name)
        # Search for the log with given ObjectId
        log = collections[collection_name].find_one(
            {"_id": ObjectId(id)},
            {"_id": 0, "hash":0, "previous_hash": 0}
        )

        if log:
            return jsonify(log)
        else:
            return jsonify({"error": "Log not found"}), 404

    except Exception as e:
        print("[view_threat error]:", e)
        return jsonify({"error": "Server error", "details": str(e)}), 500

def mark_threat_for_review(category, type, id):
    try:
        # Validate category
        if category not in ["system", "application", "security"]:
            raise ValueError("Invalid category. Must be 'system', 'application', or 'security'.")

        # Determine the collection based on type
        collection_name = f"{category}_critical_logs" if type == "critical" else f"{category}_other_logs"
        print(f"Using collection: {collection_name}")

        # Fetch the log by ObjectId
        log = collections[collection_name].find_one(
            {"_id": ObjectId(id)},
            {}
        )

        if not log:
            return False

        # Prepare log details
        logDetails = {
            'LogID': log['_id'],
            "Category": category,
            "EventID": log.get('EventID'),
            "Level": log.get('Level'),
            'TimeCreated': log.get('TimeCreated'),
            'Source': log.get('Source'),
            'Task': log.get('Task'),
            'Computer': log.get('Computer'),
            'Message': log.get('Message'),
            'threats': log.get('threats'),
        }

        # Optional: You can include modification verification if needed here
        if type == "critical":
            log_verified = verify_logs([log], category)[0]
            if not log_verified:
                return False
            logDetails['modified'] = log_verified.get('modified')

        # Insert into the marked_as_review collection
        result = collections['marked_as_review'].insert_one(logDetails)

        if result.acknowledged:
            delete = collections[collection_name].delete_one({"_id": ObjectId(id)})
            delete = collections['threats_alerts'].delete_one({"log_id": ObjectId(id)})
            if delete.deleted_count == 1:
                if type == 'critical':
                    hash_deleted = collections[f"{category}_blockchain_hashes"].delete_one({"hash": log.get('hash')})

        return result.acknowledged

    except Exception as e:
        print("[mark_threat_for_review error]:", e)
        return False

def get_threat_count():    
    threat_alerts_count = collections["threats_alerts"].count_documents({})

    return{ 'threat_alerts_count': threat_alerts_count}