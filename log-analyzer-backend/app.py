import os
from flask import Flask,session
from flask_cors import CORS
from flask import request, jsonify,session,make_response
from functools import wraps
import joblib
import psycopg2
from werkzeug.utils import secure_filename
import csv
from datetime import datetime
from collections import defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from celery_app import make_celery
import uuid
from services import get_db_connection, parse_zscaler_log, save_logs_to_db


app = Flask(__name__)
app.secret_key = 'bd2b11b6619618c12fc9b7816c054cd15c6fb1b055a9652747b11cdb4fa23ceb'
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])
make_celery(app)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:MastersUS24!123@localhost/log_analysis")

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated



def create_logs_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs 
            (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                device TEXT,
                protocol TEXT,
                url TEXT,
                action TEXT,
                application TEXT,
                category TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                http_method TEXT,
                status_code TEXT,
                user_agent TEXT,
                username TEXT,
                threat TEXT
            )
    ''')
    conn.commit()
    cursor.close()
    conn.close()

def create_users_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL)''')
    conn.commit()
    cursor.close()
    conn.close()

def create_log_jobs_table():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS log_jobs (id UUID PRIMARY KEY,username TEXT,filename TEXT, status TEXT, progress INTEGER DEFAULT 0, error TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,completed_at TIMESTAMP)''')
    conn.commit()
    cursor.close()
    conn.close()

create_logs_table()
create_users_table()
create_log_jobs_table()

@app.route('/')
def home():
    return 'Welcome to the Log Analyzer API!'

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    hashed = generate_password_hash(password)

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, hashed))
        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except psycopg2.Error as e:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        cur.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=%s", (username,))
    result = cur.fetchone()
    cur.close()
    conn.close()

    if result and check_password_hash(result[0], password):
        session['user'] = username  
        print(f"Session data: {session}")
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/check-auth')
def check_auth():
    if 'user' in session:
        return jsonify({'loggedIn': True, 'user': session['user']})
    else:
        return jsonify({'loggedIn': False}), 401


@app.route('/upload', methods=['POST'])
@requires_auth
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    file = request.files['file']
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return jsonify({'message': 'File uploaded successfully', 'filename': filename})


@app.route('/analyze-zscaler', methods=['POST'])
@requires_auth
def analyze_zscaler():
    from tasks import process_log_file
    data = request.get_json()
    filename = data.get('filename')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    job_id = uuid.uuid4()
    username = session['user']
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO log_jobs (id, username, filename, status) VALUES (%s, %s,%s, %s)''', (job_id, username, filename, 'Pending'))
    conn.commit()
    cursor.close()
    conn.close()
    process_log_file.delay(job_id, username, file_path)
    return jsonify({"job_id": job_id,"status": "Processing"}), 202

@app.route('/job-status/<job_id>', methods=['GET'])
@requires_auth  
def job_status(job_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''SELECT status, progress,error FROM log_jobs WHERE id=%s''', (job_id,))
    job = cursor.fetchone()
    cursor.close()
    conn.close()
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify({"status": job[0],"progress": job[1],"error": job[2]}), 200

@app.route('/analyze-db-logs', methods=['GET'])
@requires_auth
def analyze_db_logs():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch only necessary fields from DB
    cursor.execute('''
        SELECT timestamp,url,source_ip,threat
        FROM logs 
        WHERE action = 'Blocked'
        LIMIT 15
    ''')
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    blocked_threats = []
    for row in rows:
        blocked_threats.append({
            "timestamp": row[0],
            "url": row[1],
            "source_ip":row[2],
            "threat":row[3]
            })
    #print(blocked_threats)
    return jsonify(blocked_threats)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user', None)
    response  = make_response(jsonify({'message': 'Logged out successfully'}), 200)
    response.set_cookie('session', '', expires=0)
    return response

if __name__ == '__main__':
    app.run()
