from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'worker' or 'manager'
    worker_id = db.Column(db.String(10), db.ForeignKey('workers.worker_id'), nullable=True)
    telegram_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    worker = db.relationship('Worker', backref='user', lazy=True)
    
class Worker(db.Model):
    __tablename__ = 'workers'
    
    worker_id = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    helmet_id = db.Column(db.String(10), nullable=False)
    department = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(15), nullable=True)
    is_active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class HelmetLog(db.Model):
    __tablename__ = 'helmet_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.String(10), db.ForeignKey('workers.worker_id'), nullable=False)
    helmet_id = db.Column(db.String(10), nullable=False)
    gas = db.Column(db.Integer, nullable=False)
    temperature = db.Column(db.Float, nullable=False)
    helmet_worn = db.Column(db.Boolean, nullable=False)
    fall = db.Column(db.Boolean, nullable=False)
    risk_score = db.Column(db.Integer, nullable=False)
    battery = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    worker = db.relationship('Worker', backref='logs', lazy=True)
    
class WorkSession(db.Model):
    __tablename__ = 'work_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.String(10), db.ForeignKey('workers.worker_id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    duration = db.Column(db.Integer, nullable=True)  # in seconds
    is_completed = db.Column(db.Boolean, default=False)
    
    worker = db.relationship('Worker', backref='sessions', lazy=True)
    
class Alert(db.Model):
    __tablename__ = 'alerts'
    
    id = db.Column(db.Integer, primary_key=True)
    worker_id = db.Column(db.String(10), db.ForeignKey('workers.worker_id'), nullable=False)
    helmet_id = db.Column(db.String(10), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False)  # 'gas', 'temperature', 'fall', 'helmet', 'sos'
    risk_score = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged = db.Column(db.Boolean, default=False)
    acknowledged_by = db.Column(db.String(50), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    
    worker = db.relationship('Worker', backref='alerts', lazy=True)

def init_db():
    db.create_all()
    
    # Create default manager account if not exists
    from werkzeug.security import generate_password_hash
    from app import app
    
    with app.app_context():
        if not User.query.filter_by(username='manager').first():
            manager = User(
                username='manager',
                password_hash=generate_password_hash('manager123'),
                role='manager',
                telegram_id=Config.MANAGER_CHAT_ID
            )
            db.session.add(manager)
            db.session.commit()
            
        # Create some sample workers for testing
        sample_workers = [
            Worker(worker_id='WKR001', name='John Smith', helmet_id='HLM001', department='Construction'),
            Worker(worker_id='WKR002', name='Emma Wilson', helmet_id='HLM002', department='Mining'),
            Worker(worker_id='WKR003', name='David Lee', helmet_id='HLM003', department='Manufacturing'),
        ]
        
        for worker in sample_workers:
            if not Worker.query.filter_by(worker_id=worker.worker_id).first():
                db.session.add(worker)
                db.session.commit()
                
                # Create worker user account
                user = User(
                    username=f'worker{worker.worker_id[-3:]}',
                    password_hash=generate_password_hash('worker123'),
                    role='worker',
                    worker_id=worker.worker_id,
                    telegram_id=f'WORKER_{worker.worker_id}'  # To be updated with actual Telegram ID
                )
                db.session.add(user)
                db.session.commit()
