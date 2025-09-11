from flask import Flask, jsonify, request
import json

app = Flask(__name__)

# Load your JSON data
def load_data():
    with open('data.json') as json_file:
        return json.load(json_file)

def save_data(data):
    with open('data.json', 'w') as json_file:
        json.dump(data, json_file)

@app.route('/api/data', methods=['GET'])
def get_data():
    data = load_data()
    return jsonify(data)

@app.route('/api/data', methods=['POST'])
def add_data():
    new_entry = request.json
    data = load_data()
    data.append(new_entry)
    save_data(data)
    return jsonify(new_entry), 201

@app.route('/api/data/<int:item_id>', methods=['PUT'])
def update_data(item_id):
    updated_entry = request.json
    data = load_data()

    if item_id < 0 or item_id >= len(data):
        return jsonify({"error": "Item not found"}), 404

    data[item_id] = updated_entry
    save_data(data)
    return jsonify(updated_entry)

@app.route('/api/data/<int:item_id>', methods=['DELETE'])
def delete_data(item_id):
    data = load_data()

    if item_id < 0 or item_id >= len(data):
        return jsonify({"error": "Item not found"}), 404

    deleted_entry = data.pop(item_id)
    save_data(data)
    return jsonify(deleted_entry), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
