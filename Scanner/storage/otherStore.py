from config.mongo_confing import collections
from storage.storeThreats import storeThreat

def store_other_logs(logs, type):
    """
    Stores multiple logs in the 'other_logs_collection'.
    
    :param logs: List of dictionaries, each containing log details.
    """
    if not isinstance(logs, list) or not all(isinstance(log, dict) for log in logs):
        raise ValueError("Logs must be a list of dictionaries")

    if logs:
        # collections[f"{type}_other_logs"].insert_many(logs)
        # print(f"{len(logs)} logs stored in 'other_logs_collection' successfully.")

        for log in logs:
            result = collections[f"{type}_other_logs"].insert_one(log)

            inserted_id = result.inserted_id

            # Add the _id back to the log
            log['_id'] = inserted_id

            # If threats exist, pass the _id and threats to storeThreat
            if 'threats' in log and log['threats']:
                storeThreat(log['_id'], log['threats'], type, 'other')
                
        print(f"{len(logs)} logs stored and processed in '{type}_other_logs' successfully.")
