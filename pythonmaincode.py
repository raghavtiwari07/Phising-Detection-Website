from flask import Flask, render_template, jsonify

app = Flask(__name__)

# Simulated data for demonstration
data = {
    'cleanCount': 6,
    'suspiciousCount': 9,
    'maliciousCount': 15,
    'cleanList': ['Abusix', 'Acronis', 'ADMINUSLabs', 'AICC (MONITORAPP)', 'alphaMountain.ai', 'AlphaSOC'],
    'suspiciousList': ['www.suspicious.com', 'www.questionablesite.com', 'www.dodgywebsite.com', 'www.untrustedsite.com', 'www.shadysite.com', 'www.sketchyweb.com', 'www.unsafeexample.com', 'www.doubtfulsite.com', 'www.suspectedsite.com'],
    'maliciousList': ['www.malicioussite.com', 'www.harmfulsite.com', 'www.dangerouswebsite.com', 'www.infectedsite.com', 'www.virussite.com', 'www.exploitingsite.com', 'www.trojansite.com', 'www.phishingsite.com', 'www.attacksite.com', 'www.malwaresite.com', 'www.risksite.com', 'www.unwantedsite.com', 'www.hackingsite.com', 'www.maliciousexample.com', 'www.threateningsite.com']
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard_2.html', data=data)

@app.route('/data')
def get_data():
    # Return the data as JSON
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True)
