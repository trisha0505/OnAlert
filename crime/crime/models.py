from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import requests

# Just declare db, don't initialize it
db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Add email field
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_police = db.Column(db.Boolean, default=False)  # New field to identify police officers
    badge_number = db.Column(db.String(20), unique=True, nullable=True)  # Police badge number
    department = db.Column(db.String(100), nullable=True)  # Police department name
    rank = db.Column(db.String(50), nullable=True)  # Police officer rank
    jurisdiction = db.Column(db.String(100), nullable=True)  # Police officer's jurisdiction
    fake_reports_count = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    account_status = db.Column(db.String(20), default='active')  # active, warned, blocked
    last_warning_date = db.Column(db.DateTime, nullable=True)
    reports = db.relationship('CrimeReport', backref='author', lazy=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    two_factor_code = db.Column(db.String(6), nullable=True)
    emergency_contacts = db.relationship('EmergencyContact', backref='user', lazy=True)  # New relationship for emergency contacts
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    last_active = db.Column(db.DateTime, default=datetime.utcnow)
    current_cases = db.Column(db.Integer, default=0)
    max_cases = db.Column(db.Integer, default=10)

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        
    def check_password(self, password):
        """Check if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)
        
    def set_password(self, password):
        """Set a password for the user."""
        self.password_hash = generate_password_hash(password)

    def update_jurisdiction(self, latitude, longitude):
        """Update user's jurisdiction based on location."""
        self.latitude = latitude
        self.longitude = longitude
        
        # Use reverse geocoding to get the jurisdiction
        try:
            geocoding_url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
            response = requests.get(geocoding_url, headers={'User-Agent': 'OnAlert/1.0'})
            if response.status_code == 200:
                location_data = response.json()
                # Extract city/district from the address
                address = location_data.get('address', {})
                self.jurisdiction = address.get('city', address.get('district', address.get('suburb')))
        except Exception as e:
            print(f"Error updating jurisdiction: {str(e)}")
            
        db.session.commit()
    
    def can_take_case(self):
        """Check if officer can take more cases."""
        return self.current_cases < self.max_cases
    
    def assign_case(self):
        """Assign a new case to the officer."""
        if self.can_take_case():
            self.current_cases += 1
            self.last_active = datetime.utcnow()
            db.session.commit()
            return True
        return False
    
    def close_case(self):
        """Close a case and reduce current case count."""
        if self.current_cases > 0:
            self.current_cases -= 1
            db.session.commit()
            return True
        return False

    @staticmethod
    def get_available_officers(jurisdiction):
        """Get available police officers in a jurisdiction, sorted by workload."""
        return User.query.filter(
            User.is_police == True,
            User.jurisdiction == jurisdiction,
            User.current_cases < User.max_cases
        ).order_by(User.current_cases.asc()).all()

class CrimeReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    notes = db.Column(db.Text, nullable=True)
    evidence_file = db.Column(db.String(255), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_status = db.Column(db.String(20), default='pending')
    action_taken = db.Column(db.Text, nullable=True)
    suspect_description = db.Column(db.Text, nullable=True)
    suspect_sketch = db.Column(db.String(255), nullable=True)

    def __init__(self, **kwargs):
        super(CrimeReport, self).__init__(**kwargs)
        self.updated_at = self.timestamp

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    details = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)

class EmergencyContact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=True)
    relationship = db.Column(db.String(50), nullable=True)
    is_primary = db.Column(db.Boolean, default=False)

class SOSAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='active')  # active, responded, resolved
    message = db.Column(db.Text, nullable=True)
    responder_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    responder_notes = db.Column(db.Text, nullable=True)
    
    # Define relationships
    user = db.relationship('User', foreign_keys=[user_id], backref='sos_alerts')
    responder = db.relationship('User', foreign_keys=[responder_id], backref='responses')