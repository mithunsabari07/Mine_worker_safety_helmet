from flask import Flask, render_template, jsonify, request, redirect, url_for, flash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import json
import requests
import threading
import time
from functools import wraps

from config import Config
from database import db, User, Worker, HelmetLog, WorkSession, Alert, init_db

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
jwt = JWTManager(app)
CORS(app)

# Telegram bot
telegram_bot_token = Config.TELEGRAM_BOT_TOKEN
telegram_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"

# Store active work sessions
active_sessions = {}

# Risk calculation engine
class RiskEngine:
    @staticmethod
    def calculate_risk(data):
        risk_score = 0
        alerts = []
        
        # Gas risk
        if data['gas'] > Config.GAS_THRESHOLD:
            risk_score += 30
            alerts.append('High gas concentration detected')
        
        # Temperature risk
        if data['temperature'] > Config.TEMP_THRESHOLD:
            risk_score += 25
            alerts.append(f'High temperature: {data["temperature"]}°C')
        
        # Helmet not worn
        if not data['helmet_worn']:
            risk_score += 20
            alerts.append('Helmet not worn')
        
        # Fall detected
        if data['fall']:
            risk_score += 25
            alerts.append('Fall detected')
        
        return risk_score, alerts
    
    @staticmethod
    def get_risk_level(score):
        if score <= Config.RISK_SAFE:
            return 'safe', 'green'
        elif score <= Config.RISK_WARNING:
            return 'warning', 'orange'
        else:
            return 'danger', 'red'

# Work session tracker
class WorkSessionTracker:
    @staticmethod
    def handle_helmet_status(worker_id, helmet_worn):
        now = datetime.utcnow()
        
        if helmet_worn:
            # Helmet is worn - start or resume session
            if worker_id not in active_sessions:
                # Start new session
                session = WorkSession(
                    worker_id=worker_id,
                    start_time=now,
                    is_completed=False
                )
                db.session.add(session)
                db.session.commit()
                active_sessions[worker_id] = {
                    'session_id': session.id,
                    'start_time': now,
                    'last_pause': None,
                    'total_pause_duration': 0
                }
            else:
                # Resume existing session
                session_data = active_sessions[worker_id]
                if session_data['last_pause']:
                    pause_duration = (now - session_data['last_pause']).total_seconds()
                    if pause_duration > 300:  # 5 minutes
                        # End old session and start new one
                        WorkSessionTracker._end_session(worker_id, now)
                        new_session = WorkSession(
                            worker_id=worker_id,
                            start_time=now,
                            is_completed=False
                        )
                        db.session.add(new_session)
                        db.session.commit()
                        active_sessions[worker_id] = {
                            'session_id': new_session.id,
                            'start_time': now,
                            'last_pause': None,
                            'total_pause_duration': 0
                        }
                    else:
                        # Resume same session
                        session_data['total_pause_duration'] += pause_duration
                        session_data['last_pause'] = None
        else:
            # Helmet removed - pause session
            if worker_id in active_sessions and not active_sessions[worker_id]['last_pause']:
                active_sessions[worker_id]['last_pause'] = now
    
    @staticmethod
    def _end_session(worker_id, end_time):
        if worker_id in active_sessions:
            session_data = active_sessions[worker_id]
            session = WorkSession.query.get(session_data['session_id'])
            
            if session:
                actual_duration = (end_time - session.start_time).total_seconds()
                net_duration = actual_duration - session_data['total_pause_duration']
                
                session.end_time = end_time
                session.duration = int(net_duration)
                session.is_completed = True
                db.session.commit()
            
            del active_sessions[worker_id]
    
    @staticmethod
    def get_worker_hours(worker_id, period='today'):
        now = datetime.utcnow()
        
        if period == 'today':
            start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
            sessions = WorkSession.query.filter(
                WorkSession.worker_id == worker_id,
                WorkSession.start_time >= start_date,
                WorkSession.is_completed == True
            ).all()
        elif period == 'week':
            start_date = now - timedelta(days=7)
            sessions = WorkSession.query.filter(
                WorkSession.worker_id == worker_id,
                WorkSession.start_time >= start_date,
                WorkSession.is_completed == True
            ).all()
        else:  # month
            start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            sessions = WorkSession.query.filter(
                WorkSession.worker_id == worker_id,
                WorkSession.start_time >= start_date,
                WorkSession.is_completed == True
            ).all()
        
        total_seconds = sum(session.duration for session in sessions if session.duration)
        
        # Add current active session
        if worker_id in active_sessions:
            current_session = active_sessions[worker_id]
            if not current_session['last_pause']:  # Not paused
                current_duration = (now - current_session['start_time']).total_seconds()
                total_seconds += current_duration - current_session['total_pause_duration']
        
        hours = total_seconds / 3600
        return round(hours, 2)

# Alert system
class AlertSystem:
    @staticmethod
    def send_telegram_alert(chat_id, message):
        if telegram_bot_token and chat_id:
            try:
                payload = {
                    'chat_id': chat_id,
                    'text': message,
                    'parse_mode': 'HTML'
                }
                response = requests.post(telegram_url, json=payload, timeout=5)
                return response.status_code == 200
            except:
                return False
        return False
    
    @staticmethod
    def create_alert(worker_id, helmet_id, risk_score, alerts_list):
        worker = Worker.query.filter_by(worker_id=worker_id).first()
        if not worker:
            return
        
        # Create alert record
        alert = Alert(
            worker_id=worker_id,
            helmet_id=helmet_id,
            alert_type=','.join([a.split(':')[0] for a in alerts_list]),
            risk_score=risk_score,
            message='; '.join(alerts_list),
            timestamp=datetime.utcnow()
        )
        db.session.add(alert)
        db.session.commit()
        
        # Send Telegram alerts
        alert_message = f"🚨 <b>SAFETY ALERT</b> 🚨\n"
        alert_message += f"Worker: {worker.name}\n"
        alert_message += f"ID: {worker_id}\n"
        alert_message += f"Risk Score: {risk_score}\n"
        alert_message += f"Alerts: {', '.join(alerts_list)}\n"
        alert_message += f"Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
        
        # Send to manager
        manager = User.query.filter_by(role='manager').first()
        if manager and manager.telegram_id:
            AlertSystem.send_telegram_alert(manager.telegram_id, alert_message)
        
        # Send to worker
        worker_user = User.query.filter_by(worker_id=worker_id).first()
        if worker_user and worker_user.telegram_id:
            AlertSystem.send_telegram_alert(worker_user.telegram_id, alert_message)

# Authentication decorators
def role_required(role):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            current_user = get_jwt_identity()
            user = User.query.filter_by(username=current_user).first()
            
            if not user or user.role != role:
                return jsonify({'error': 'Unauthorized'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=username)
            response = redirect(url_for('dashboard'))
            response.set_cookie('access_token', access_token)
            
            # Store user info in session
            from flask import session
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['worker_id'] = user.worker_id
            
            return response
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    access_token = request.cookies.get('access_token')
    if not access_token:
        return redirect(url_for('login'))
    
    # Verify token
    from flask_jwt_extended import decode_token
    try:
        decoded_token = decode_token(access_token)
        username = decoded_token['sub']
        user = User.query.filter_by(username=username).first()
        
        if user.role == 'worker':
            return redirect(url_for('worker_dashboard'))
        else:
            return redirect(url_for('manager_dashboard'))
    except:
        return redirect(url_for('login'))

@app.route('/worker/dashboard')
@role_required('worker')
def worker_dashboard():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    worker = Worker.query.filter_by(worker_id=user.worker_id).first()
    
    # Get latest log
    latest_log = HelmetLog.query.filter_by(worker_id=worker.worker_id)\
        .order_by(HelmetLog.timestamp.desc())\
        .first()
    
    # Get today's hours
    today_hours = WorkSessionTracker.get_worker_hours(worker.worker_id, 'today')
    
    # Get recent alerts
    recent_alerts = Alert.query.filter_by(worker_id=worker.worker_id)\
        .order_by(Alert.timestamp.desc())\
        .limit(5)\
        .all()
    
    return render_template('worker_dashboard.html',
                         worker=worker,
                         latest_log=latest_log,
                         today_hours=today_hours,
                         recent_alerts=recent_alerts)

@app.route('/manager/dashboard')
@role_required('manager')
def manager_dashboard():
    # Get all workers
    workers = Worker.query.all()
    
    # Get active workers (with helmet on)
    active_workers = []
    for worker in workers:
        latest_log = HelmetLog.query.filter_by(worker_id=worker.worker_id)\
            .order_by(HelmetLog.timestamp.desc())\
            .first()
        
        if latest_log and latest_log.helmet_worn:
            risk_level = RiskEngine.get_risk_level(latest_log.risk_score)[0]
            worker_data = {
                'worker_id': worker.worker_id,
                'name': worker.name,
                'department': worker.department,
                'helmet_id': worker.helmet_id,
                'risk_score': latest_log.risk_score,
                'risk_level': risk_level,
                'last_update': latest_log.timestamp,
                'is_active': True
            }
        else:
            worker_data = {
                'worker_id': worker.worker_id,
                'name': worker.name,
                'department': worker.department,
                'helmet_id': worker.helmet_id,
                'risk_score': 0,
                'risk_level': 'inactive',
                'last_update': None,
                'is_active': False
            }
        
        # Get today's hours
        worker_data['today_hours'] = WorkSessionTracker.get_worker_hours(worker.worker_id, 'today')
        active_workers.append(worker_data)
    
    # Get unacknowledged alerts
    unacknowledged_alerts = Alert.query.filter_by(acknowledged=False)\
        .order_by(Alert.timestamp.desc())\
        .limit(10)\
        .all()
    
    return render_template('manager_dashboard.html',
                         workers=active_workers,
                         alerts=unacknowledged_alerts)

# API Endpoints
@app.route('/api/helmet/data', methods=['POST'])
def receive_helmet_data():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['worker_id', 'helmet_id', 'helmet_worn', 'gas', 'temperature', 'fall']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing field: {field}'}), 400
        
        # Convert types
        worker_id = str(data['worker_id'])
        helmet_id = str(data['helmet_id'])
        helmet_worn = bool(data['helmet_worn'])
        gas = int(data['gas'])
        temperature = float(data['temperature'])
        fall = bool(data['fall'])
        
        # Calculate risk score
        risk_score, alerts = RiskEngine.calculate_risk({
            'gas': gas,
            'temperature': temperature,
            'helmet_worn': helmet_worn,
            'fall': fall
        })
        
        # Create helmet log
        log = HelmetLog(
            worker_id=worker_id,
            helmet_id=helmet_id,
            gas=gas,
            temperature=temperature,
            helmet_worn=helmet_worn,
            fall=fall,
            risk_score=risk_score,
            battery=data.get('battery', 0.0),
            timestamp=datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
        
        # Handle work session tracking
        WorkSessionTracker.handle_helmet_status(worker_id, helmet_worn)
        
        # Check for alerts
        if risk_score >= Config.RISK_WARNING and alerts:
            AlertSystem.create_alert(worker_id, helmet_id, risk_score, alerts)
        
        # Determine buzzer status
        buzzer_status = "ON" if risk_score >= Config.RISK_WARNING else "OFF"
        
        return jsonify({
            'status': 'success',
            'risk_score': risk_score,
            'risk_level': RiskEngine.get_risk_level(risk_score)[0],
            'buzzer': buzzer_status
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/worker/status')
@role_required('worker')
def get_worker_status():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if not user.worker_id:
        return jsonify({'error': 'Worker not found'}), 404
    
    # Get latest log
    latest_log = HelmetLog.query.filter_by(worker_id=user.worker_id)\
        .order_by(HelmetLog.timestamp.desc())\
        .first()
    
    if not latest_log:
        return jsonify({
            'status': 'offline',
            'message': 'No helmet data available'
        }), 200
    
    risk_level, color = RiskEngine.get_risk_level(latest_log.risk_score)
    
    return jsonify({
        'worker_id': user.worker_id,
        'helmet_worn': latest_log.helmet_worn,
        'gas': latest_log.gas,
        'temperature': latest_log.temperature,
        'fall': latest_log.fall,
        'risk_score': latest_log.risk_score,
        'risk_level': risk_level,
        'battery': latest_log.battery,
        'last_update': latest_log.timestamp.isoformat(),
        'today_hours': WorkSessionTracker.get_worker_hours(user.worker_id, 'today')
    })

@app.route('/api/manager/workers')
@role_required('manager')
def get_all_workers():
    workers = Worker.query.all()
    
    result = []
    for worker in workers:
        latest_log = HelmetLog.query.filter_by(worker_id=worker.worker_id)\
            .order_by(HelmetLog.timestamp.desc())\
            .first()
        
        worker_data = {
            'worker_id': worker.worker_id,
            'name': worker.name,
            'department': worker.department,
            'helmet_id': worker.helmet_id,
            'is_active': worker.is_active
        }
        
        if latest_log:
            risk_level, color = RiskEngine.get_risk_level(latest_log.risk_score)
            worker_data.update({
                'gas': latest_log.gas,
                'temperature': latest_log.temperature,
                'helmet_worn': latest_log.helmet_worn,
                'risk_score': latest_log.risk_score,
                'risk_level': risk_level,
                'last_update': latest_log.timestamp.isoformat(),
                'today_hours': WorkSessionTracker.get_worker_hours(worker.worker_id, 'today'),
                'week_hours': WorkSessionTracker.get_worker_hours(worker.worker_id, 'week'),
                'month_hours': WorkSessionTracker.get_worker_hours(worker.worker_id, 'month')
            })
        
        result.append(worker_data)
    
    return jsonify(result)

@app.route('/api/alerts')
@jwt_required()
def get_alerts():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user).first()
    
    if user.role == 'worker':
        alerts = Alert.query.filter_by(worker_id=user.worker_id)\
            .order_by(Alert.timestamp.desc())\
            .limit(50)\
            .all()
    else:
        alerts = Alert.query.order_by(Alert.timestamp.desc())\
            .limit(100)\
            .all()
    
    result = []
    for alert in alerts:
        worker = Worker.query.filter_by(worker_id=alert.worker_id).first()
        result.append({
            'id': alert.id,
            'worker_name': worker.name if worker else 'Unknown',
            'worker_id': alert.worker_id,
            'alert_type': alert.alert_type,
            'risk_score': alert.risk_score,
            'message': alert.message,
            'timestamp': alert.timestamp.isoformat(),
            'acknowledged': alert.acknowledged,
            'acknowledged_by': alert.acknowledged_by,
            'time_ago': get_time_ago(alert.timestamp)
        })
    
    return jsonify(result)

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@role_required('manager')
def acknowledge_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    
    alert.acknowledged = True
    alert.acknowledged_by = get_jwt_identity()
    alert.acknowledged_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/api/reports/daily')
@role_required('manager')
def get_daily_report():
    today = datetime.utcnow().date()
    start_date = datetime.combine(today, datetime.min.time())
    end_date = datetime.combine(today, datetime.max.time())
    
    # Get all logs for today
    logs = HelmetLog.query.filter(
        HelmetLog.timestamp >= start_date,
        HelmetLog.timestamp <= end_date
    ).all()
    
    # Get all sessions for today
    sessions = WorkSession.query.filter(
        WorkSession.start_time >= start_date,
        WorkSession.start_time <= end_date,
        WorkSession.is_completed == True
    ).all()
    
    report = {
        'date': today.isoformat(),
        'total_workers': Worker.query.count(),
        'active_workers': len([w for w in Worker.query.all() if w.is_active]),
        'high_risk_incidents': len([l for l in logs if l.risk_score >= Config.RISK_WARNING]),
        'total_alerts': Alert.query.filter(
            Alert.timestamp >= start_date,
            Alert.timestamp <= end_date
        ).count(),
        'total_work_hours': sum(s.duration for s in sessions if s.duration) / 3600,
        'average_risk_score': sum(l.risk_score for l in logs) / len(logs) if logs else 0
    }
    
    return jsonify(report)

@app.route('/logout')
def logout():
    response = redirect(url_for('login'))
    response.delete_cookie('access_token')
    
    from flask import session
    session.clear()
    
    return response

def get_time_ago(timestamp):
    now = datetime.utcnow()
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hours ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minutes ago"
    else:
        return "Just now"

# Initialize database
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
