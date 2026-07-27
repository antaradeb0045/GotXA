#!/usr/bin/env python3
"""
SIEM server with SQL database storage and REST API.
Receives logs via HTTP, parses them, stores in PostgreSQL, and triggers alerts.
"""

from flask import Flask, request, jsonify, render_template
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import logging
import os
from collections import defaultdict

app = Flask(__name__)

# Database config
DB_HOST = os.getenv('DB_HOST', 'siem-postgres')
DB_PORT = os.getenv('DB_PORT', 5432)
DB_NAME = os.getenv('DB_NAME', 'siem_db')
DB_USER = os.getenv('DB_USER', 'siem_user')
DB_PASS = os.getenv('DB_PASS', 'siem_password')

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def get_db_connection():
    """Get database connection."""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASS
        )
        return conn
    except Exception as e:
        logger.error(f"DB connection failed: {e}")
        return None

def init_db():
    """Initialize database schema."""
    conn = get_db_connection()
    if not conn:
        logger.error("Cannot initialize DB - connection failed")
        return False
    
    try:
        cursor = conn.cursor()
        
        # Create logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP,
                level VARCHAR(10),
                message TEXT,
                host VARCHAR(255),
                ingested_at TIMESTAMP DEFAULT NOW(),
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host);
            CREATE INDEX IF NOT EXISTS idx_logs_level ON logs(level);
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp);
        """)
        
        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT NOW(),
                host VARCHAR(255),
                severity VARCHAR(10),
                rule VARCHAR(255),
                log_message TEXT,
                log_id INTEGER REFERENCES logs(id),
                created_at TIMESTAMP DEFAULT NOW()
            );
            
            CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"DB init failed: {e}")
        return False

@app.route('/logs/ingest', methods=['POST'])
def ingest_logs():
    """Endpoint to receive and store logs."""
    try:
        data = request.get_json()
        print(f"[DEBUG] Raw request data: {data}")
        logger.info(f"[INGEST] Received payload: {json.dumps(data)[:200]}")
        if not data:
            return jsonify({"error": "No JSON data"}), 400
        
        events = data if isinstance(data, list) else [data]
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB connection failed"}), 500
        
        cursor = conn.cursor()
        ingested_count = 0
        
        for event in events:
            try:
                timestamp = event.get('timestamp') or datetime.utcnow().isoformat()
                level = event.get('level', 'INFO')
                message = event.get('message', '')
                host = event.get('host', 'unknown')
                
                # Insert log
                cursor.execute("""
                    INSERT INTO logs (timestamp, level, message, host, ingested_at, created_at)
                    VALUES (%s, %s, %s, %s, NOW(), NOW())
                    RETURNING id;
                """, (timestamp, level, message, host))
                
                log_id = cursor.fetchone()[0]
                
                # Check alert rules
                check_alerts(cursor, log_id, host, message, level)
                
                ingested_count += 1
                logger.info(f"Ingested log from {host}: {message[:50]}")
            except Exception as e:
                logger.error(f"Error processing event: {e}")
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return jsonify({
            "status": "success",
            "logs_ingested": ingested_count
        }), 200
    except Exception as e:
        logger.error(f"Error in ingest_logs: {e}")
        return jsonify({"error": str(e)}), 500

def check_alerts(cursor, log_id, host, message, level):
    """Generate alerts based on log content."""
    message_lower = (message or '').lower()
    # Security attack detection rules
    security_patterns = {
        "Brute Force Attack": ["brute force", "multiple login failures", "failed password"],
        "SQL Injection": ["sql injection", "select * from", "union select"],
        "Unauthorized Access": ["unauthorized", "illegal access"],
        "Malware Detection": ["malware", "virus", "trojan"]
    }

    for alert_name, patterns in security_patterns.items():
        if any(pattern in message_lower for pattern in patterns):
            cursor.execute("""
                INSERT INTO alerts (timestamp, host, severity, rule, log_message, log_id)
                VALUES (NOW(), %s, %s, %s, %s, %s);
            """, (host, 'HIGH', alert_name, message, log_id))
    
    # Alert rule 1: Error patterns
    if any(word in message_lower for word in ['error', 'fail', 'critical', 'exception']):
        cursor.execute("""
            INSERT INTO alerts (timestamp, host, severity, rule, log_message, log_id)
            VALUES (NOW(), %s, %s, %s, %s, %s);
        """, (host, 'HIGH', 'Error detected', message, log_id))
        logger.warning(f"ALERT: Error on {host} - {message}")
    
    # Alert rule 2: Warn level
    if level.upper() == 'WARN':
        cursor.execute("""
            INSERT INTO alerts (timestamp, host, severity, rule, log_message, log_id)
            VALUES (NOW(), %s, %s, %s, %s, %s);
        """, (host, 'MEDIUM', 'Warning detected', message, log_id))

@app.route('/status', methods=['GET'])
def status():
    """Health check and stats endpoint."""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"status": "db_error"}), 500
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT COUNT(*) as count FROM logs;")
        total_logs = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM alerts;")
        total_alerts = cursor.fetchone()['count']
        
        cursor.execute("""
            SELECT severity, COUNT(*) as count FROM alerts 
            GROUP BY severity;
        """)
        alert_summary = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "status": "running",
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "alert_summary": alert_summary
        }), 200
    except Exception as e:
        logger.error(f"Error in status: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/logs', methods=['GET'])
def get_logs():
    """Retrieve recent logs (last 100)."""
    try:
        limit = request.args.get('limit', 100, type=int)
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB error"}), 500
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, timestamp, level, message, host, ingested_at
            FROM logs
            ORDER BY created_at DESC
            LIMIT %s;
        """, (limit,))
        
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify([dict(row) for row in rows]), 200
    except Exception as e:
        logger.error(f"Error in get_logs: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Retrieve recent alerts (last 100)."""
    try:
        limit = request.args.get('limit', 100, type=int)
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB error"}), 500
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        cursor.execute("""
            SELECT id, timestamp, host, severity, rule, log_message
            FROM alerts
            ORDER BY created_at DESC
            LIMIT %s;
        """, (limit,))
        
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return jsonify([dict(row) for row in rows]), 200
    except Exception as e:
        logger.error(f"Error in get_alerts: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/', methods=['GET'])
def dashboard():
    """Serve the dashboard HTML."""
    return render_template('dashboard.html')

@app.route('/api/dashboard-data', methods=['GET'])
def dashboard_data():
    """Get aggregated data for the dashboard."""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"error": "DB error"}), 500
        
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        # Total stats
        cursor.execute("SELECT COUNT(*) as count FROM logs;")
        total_logs = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM alerts;")
        total_alerts = cursor.fetchone()['count']
        
        # Logs by level
        cursor.execute("""
            SELECT level, COUNT(*) as count FROM logs 
            GROUP BY level 
            ORDER BY count DESC;
        """)
        logs_by_level = {row['level']: row['count'] for row in cursor.fetchall()}
        
        # Alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count FROM alerts 
            GROUP BY severity;
        """)
        alerts_by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # Logs by host
        cursor.execute("""
            SELECT host, COUNT(*) as count FROM logs 
            GROUP BY host 
            ORDER BY count DESC
            LIMIT 10;
        """)
        logs_by_host = {row['host']: row['count'] for row in cursor.fetchall()}
        
        # Recent logs
        cursor.execute("""
            SELECT id, timestamp, level, message, host 
            FROM logs 
            ORDER BY created_at DESC 
            LIMIT 20;
        """)
        recent_logs = [dict(row) for row in cursor.fetchall()]
        
        # Recent alerts
        cursor.execute("""
            SELECT id, timestamp, host, severity, rule, log_message 
            FROM alerts 
            ORDER BY created_at DESC 
            LIMIT 20;
        """)
        recent_alerts = [dict(row) for row in cursor.fetchall()]
        
        cursor.close()
        conn.close()
        
        return jsonify({
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "logs_by_level": logs_by_level,
            "alerts_by_severity": alerts_by_severity,
            "logs_by_host": logs_by_host,
            "recent_logs": recent_logs,
            "recent_alerts": recent_alerts
        }), 200
    except Exception as e:
        logger.error(f"Error in dashboard_data: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    logger.info("Initializing SIEM database...")
    init_db()
    logger.info("SIEM Server starting on port 5000...")
    app.run(host='0.0.0.0', port=5000, debug=False)
