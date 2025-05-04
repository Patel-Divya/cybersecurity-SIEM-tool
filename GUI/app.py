import os
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import fetch as functions

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_FOLDER = os.path.join(BASE_DIR, 'dashboard')

app = Flask(__name__)
app.secret_key = "log-scanner"

CORS(app)

@app.route('/getMarkedAsReview')
def getReviewLogs():
    return functions.allMarkedAsReview()

@app.route('/markAsReview', methods=['POST'])
def markAsReview():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    category = data.get('category', '').lower()
    level = data.get('level', '')
    timeStamp = data.get('time','')
    eventId = data.get('eventId','')
    
    if category and level and timeStamp and eventId:
        result = functions.markAsReview(category, level, eventId, timeStamp)
        if result:
            result = functions.delete_log(eventId, timeStamp, level, category)
            return jsonify({'success': True, 'message': 'Log marked successfully'})
        else:
            return jsonify({'success': False, 'message': 'Log not found or marking failed'}), 404
    else:
        return jsonify({'error': 'Missing required fields'}), 400

@app.route('/countLogs', methods=['GET'])
def countLogs():
    category = request.args.get('category', '').lower()
    
    if not category:
        return jsonify({'error': 'Missing category'}), 400
    
    return functions.count_logs(category)

@app.route('/getLogs', methods=['GET'])
def getLogs():
    category = request.args.get('category', '').lower()
    level = request.args.get('level', '').lower()

    if not level or not category:
        return jsonify({'error': 'Missing category or level'}), 400

    return functions.fetch_logs_by_level(category, level)

@app.route('/delete', methods=['DELETE'])
def deleteLog():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    category = data.get('category', '').lower()
    level = data.get('level', '')
    timeStamp = data.get('time','')
    eventId = data.get('eventId','')
    
    if category and level and timeStamp and eventId:
        result = functions.delete_log(eventId, timeStamp, level, category, fromAudit=True)
        if result:
            return jsonify({'success': True, 'message': 'Log deleted successfully'})
        else:
            return jsonify({'success': False, 'message': 'Log not found or deletion failed'}), 404
    else:
        return jsonify({'error': 'Missing required fields'}), 400

@app.route('/log/<category>/<level>/<eventID>/<time>', methods=['GET'])
def getLog(category, level, eventID, time):
    category = category.lower()
    
    return functions.getLog(category, int(level), int(eventID), time)

@app.route('/resolvedCount/<category>/<level>', methods=['GET'])
def getResolvedCount(category, level):
    category = category.lower()
    level = level.lower()

    return functions.get_resolved_count(category, level)

@app.route('/resolvedLog/<category>/<level>/<eventID>/<time>', methods=['GET'])
def resolvedLog(category, level, eventID, time):
    category = category.lower()
    
    return functions.viewMarkedAsReview(category, int(level), int(eventID), time)

@app.route('/allResolvedCount', methods=['GET'])
def allResolvedCount():
    return jsonify(functions.get_all_resolved_count())

@app.route('/threat-stats', methods=['GET'])
def get_threat_stats():
    return jsonify(functions.get_threat_stats())

@app.route('/get-threats', methods=['GET'])
def get_all_threats():
    return jsonify(functions.getThreats())

@app.route('/get-threats-count', methods=['GET'])
def get_threat_count():
    return jsonify(functions.get_threat_count())

@app.route('/view-threat/<category>/<type>/<id>', methods=['GET'])
def view_threat(category, type, id):
    category = category.lower()
    type = type.lower()
    id = id.lower()
    
    return functions.view_threat(category, type, id)


@app.route('/markThreatForReview', methods=['POST'])
def markThreatForReview():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Missing JSON body'}), 400
    
    category = data.get('category', '').lower()
    type = data.get('type', '').lower()
    id = data.get('id','').lower()
    
    if category and type and id:
        result = functions.mark_threat_for_review(category, type, id)
        if result:
            return jsonify({'success': True, 'message': 'Log marked successfully'})
        else:
            return jsonify({'success': False, 'message': 'Log not found or marking failed'}), 404
    else:
        return jsonify({'error': 'Missing required fields'}), 400


# Serve pages
@app.route('/dashboard/<path:filename>', methods=['GET'])
def serve_dashboard(filename):
    return send_from_directory(DASHBOARD_FOLDER, filename)

@app.route('/<path:filename>', methods=['GET'])
def serve_file(filename):
    return send_from_directory(BASE_DIR, filename)

@app.route('/', methods=['GET'])
def serve_home():
    return send_from_directory(BASE_DIR, 'home.html')


if __name__ == '__main__':
    app.run(debug=True)
