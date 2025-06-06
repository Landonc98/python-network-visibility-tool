# app.py
# Capstone Project - Week 1
# Purpose: Begin building Flask web interface for the network visibility tool

# Import Flask class from flask module
from flask import Flask, jsonify

# Create an instance of the Flask app
# This is th core of the Flask web application
app = Flask(__name__)

# Define a basic route at the root URL ('/')
# When a user visits http://localhost:5000/, this function willl run
@app.route('/')
def home():
    # Return a simple message to confirm that the Flask app is running
    return "Network Visibility Tool Running"
# Define a route at '/packets'
# This will eventually display live packet data; for now it returns dummy data
@app.route('/packets')
def get_packets():
    # Create some dummy packet data to simulate network packets
    dummy_packets = [
        {"timestamp": "2025-06-06 18:00:00", "src": "192.168.1.2", "dst": "8.8.8.8", "proto": "TCP"},
        {"timestamp": "2025-06-06 18:01:00", "src": "192.168.1.3", "dst": "1.1.1.1", "proto": "UDP"}
    ]

    # Return the dummy packet data as a JSON response
    return jsonify(dummy_packets)

# Main block - this runs when the script is executed directly
if __name__ == '__main__':
    # Start the Flask development server
    # debug=True enables auto-reload and detailed error messages during development
    app.run (debug=True)
