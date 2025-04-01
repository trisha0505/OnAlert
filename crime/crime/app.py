from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from sqlalchemy import func, and_
import random
from stability_sdk import client
import io
import base64
from PIL import Image
from dotenv import load_dotenv
import requests
from models import db, User, CrimeReport, EmergencyContact, SOSAlert  # Import models from models.py
from passlib.hash import sha256_crypt
import secrets
import logging
import json
from functools import wraps
from flask_migrate import Migrate
import re
from pathlib import Path
from sqlalchemy import case
import pytz
import timezonefinder

# Load environment variables from .env file
load_dotenv()

# Get the Hugging Face token
hf_token = os.getenv('HUGGINGFACE_TOKEN')

if not hf_token:
    print("Error: HUGGINGFACE_TOKEN not found in environment variables")
    # Handle the error appropriately
else:
    print(f"HUGGINGFACE_TOKEN: {hf_token[:8]}...")  # Print the first 8 characters for debugging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)  # Make sessions last 30 days
app.config['SESSION_COOKIE_SECURE'] = True  # Use secure cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['DEBUG'] = os.environ.get('FLASK_ENV', 'production') == 'development'

# Get the absolute path to the database file
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'crime_report.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')  # Update upload folder path

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Set up mail configuration
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = 'onalertpolice@gmail.com'
app.config['MAIL_PASSWORD'] = 'jqcivvmrsgglwvzn'  # Use the new password you generated
app.config['MAIL_DEFAULT_SENDER'] = 'onalertpolice@gmail.com'

# Debug mail configuration
if app.config['DEBUG']:
    print(f"Mail configuration: Server={app.config['MAIL_SERVER']}, Port={app.config['MAIL_PORT']}")
    print(f"Mail username is set: {bool(app.config['MAIL_USERNAME'])}")
    print(f"Mail password is set: {bool(app.config['MAIL_PASSWORD'])}")

# Initialize extensions
db.init_app(app)  # Initialize db with app
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Create tables
with app.app_context():
    db.create_all()

# Community Resources Models
class WatchMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    area = db.Column(db.String(100), nullable=False)
    is_coordinator = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CommunityMeeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.Date, nullable=False)
    time = db.Column(db.Time, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ReportEnquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('crime_report.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    response = db.Column(db.Text)
    is_responded = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    report = db.relationship('CrimeReport', backref=db.backref('enquiries', lazy=True))
    user = db.relationship('User', backref=db.backref('report_enquiries', lazy=True))

class UserAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    crime_alerts = db.Column(db.Boolean, default=True)
    crime_radius = db.Column(db.Integer, default=2)
    crime_frequency = db.Column(db.String(20), default='daily')
    community_alerts = db.Column(db.Boolean, default=True)
    community_frequency = db.Column(db.String(20), default='weekly')
    meeting_reminders = db.Column(db.Boolean, default=True)
    emergency_alerts = db.Column(db.Boolean, default=True)
    alert_types = db.Column(db.String(200))
    emergency_location = db.Column(db.String(200))
    notify_email = db.Column(db.Boolean, default=True)
    notify_sms = db.Column(db.Boolean, default=False)
    notify_app = db.Column(db.Boolean, default=True)
    notification_sound = db.Column(db.String(20), default='default')
    silent_hours = db.Column(db.Boolean, default=False)
    silent_start = db.Column(db.String(10), default='22:00')
    silent_end = db.Column(db.String(10), default='07:00')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Add relationship to User model
    user = db.relationship('User', backref=db.backref('alerts', lazy=True))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_crime_statistics():
    now = datetime.utcnow()
    last_24_hours = now - timedelta(days=1)
    last_week = now - timedelta(weeks=1)
    this_month = now - timedelta(days=30)

    # Recent crimes
    recent_24h = CrimeReport.query.filter(CrimeReport.timestamp >= last_24_hours).count()
    recent_week = CrimeReport.query.filter(CrimeReport.timestamp >= last_week).count()

    # Active areas statistics
    high_risk_threshold = 5  # Number of crimes in an area to be considered high risk
    moderate_risk_threshold = 2  # Number of crimes in an area to be considered moderate risk

    # Group by location and count crimes in last month
    location_stats = db.session.query(
        CrimeReport.location,
        func.count(CrimeReport.id).label('crime_count')
    ).filter(CrimeReport.timestamp >= this_month).group_by(CrimeReport.location).all()

    high_risk_areas = sum(1 for loc in location_stats if loc.crime_count >= high_risk_threshold)
    moderate_risk_areas = sum(1 for loc in location_stats if moderate_risk_threshold <= loc.crime_count < high_risk_threshold)

    # Response time (average time between report submission and status change to 'investigating')
    resolved_cases = CrimeReport.query.filter(
        and_(
            CrimeReport.status == 'resolved',
            CrimeReport.timestamp >= this_month
        )
    ).all()
    
    total_response_time = sum(
        (report.updated_at - report.timestamp).total_seconds() / 60  # Convert to minutes
        for report in resolved_cases
        if hasattr(report, 'updated_at') and report.updated_at
    )
    
    avg_response_time = round(total_response_time / len(resolved_cases)) if resolved_cases else 0

    # Cases solved percentage
    total_cases_month = CrimeReport.query.filter(CrimeReport.timestamp >= this_month).count()
    solved_cases_month = CrimeReport.query.filter(
        and_(
            CrimeReport.status == 'resolved',
            CrimeReport.timestamp >= this_month
        )
    ).count()
    
    solved_percentage = round((solved_cases_month / total_cases_month * 100) if total_cases_month > 0 else 0)

    return {
        'recent_24h': recent_24h,
        'recent_week': recent_week,
        'high_risk_areas': high_risk_areas,
        'moderate_risk_areas': moderate_risk_areas,
        'avg_response_time': avg_response_time,
        'solved_percentage': solved_percentage
    }

# Routes
@app.route('/')
def home():
    """Render the home page with relevant crime listings."""
    today = datetime.now().date()
    
    # For authenticated police users, show crimes in their jurisdiction
    if current_user.is_authenticated and current_user.is_police:
        # Get crimes from police's jurisdiction, ordered by timestamp
        recent_crimes = CrimeReport.query.filter_by(location=current_user.jurisdiction)\
                              .order_by(CrimeReport.timestamp.desc())\
                              .limit(10).all()
                              
    # For authenticated regular users, prioritize their own reports and relevant local crimes
    elif current_user.is_authenticated:
        user_crimes = CrimeReport.query.filter_by(user_id=current_user.id).all()
        
        # Get other crimes to consider for relevance
        other_crimes = CrimeReport.query.filter(CrimeReport.user_id != current_user.id).all()
        
        # Calculate relevance for each crime
        crime_scores = []
        
        # First add user's own crimes with highest relevance
        for crime in user_crimes:
            crime_scores.append((crime, 100))  # Max score for user's own reports
            
        # Then calculate relevance for other crimes
        for crime in other_crimes:
            score = 0
            
            # Boost for locality match
            if current_user.jurisdiction and crime.location == current_user.jurisdiction:
                score += 40
                
            # Boost for recency (0-30 points based on age in days)
            days_old = (datetime.now() - crime.timestamp).days
            recency_score = max(0, 30 - days_old)
            score += recency_score
            
            # Boost for verified crimes
            if crime.is_verified:
                score += 20
                
            # Boost for active investigations
            if crime.status in ['pending', 'investigating']:
                score += 15
                
            crime_scores.append((crime, score))
            
        # Sort by relevance score and get top 10
        crime_scores.sort(key=lambda x: x[1], reverse=True)
        recent_crimes = [crime for crime, score in crime_scores[:10]]
        
    # For anonymous users, show relevant crimes by location and verification status
    else:
        recent_crimes = CrimeReport.query.filter_by(is_verified=True)\
                              .order_by(CrimeReport.timestamp.desc())\
                              .limit(10).all()
    
    # Get statistics for the home page
    statistics = get_crime_statistics()
        
    return render_template('home.html', recent_crimes=recent_crimes, today=today, statistics=statistics)

def calculate_solved_percentage():
    total_reports = CrimeReport.query.filter(
        CrimeReport.timestamp >= datetime.utcnow() - timedelta(days=30)
    ).count()
    
    solved_reports = CrimeReport.query.filter(
        CrimeReport.status == 'resolved',
        CrimeReport.timestamp >= datetime.utcnow() - timedelta(days=30)
    ).count()
    
    return int((solved_reports / total_reports * 100) if total_reports > 0 else 0)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Redirect if user is already logged in
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        # Basic validation
        errors = []
        
        # Username validation
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
            
        # Email validation
        if not email or '@' not in email or '.' not in email:
            errors.append('Please enter a valid email address.')
        if User.query.filter_by(email=email).first():
            errors.append('Email address is already registered.')
            
        # Password validation
        if not password:
            errors.append('Password is required.')
        else:
            if len(password) < 6:
                errors.append('Password must be at least 6 characters long.')
            if not any(c.isalpha() for c in password):
                errors.append('Password must contain at least one letter.')
            if not any(c.isdigit() for c in password):
                errors.append('Password must contain at least one number.')
            if password != confirm_password:
                errors.append('Passwords do not match.')
            
        # If there are any errors, flash them and return to signup page
        if errors:
            for error in errors:
                flash(error, 'error')
            return redirect(url_for('signup'))
            
        try:
            # Create new user
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(user)
            db.session.commit()
            
            # Send welcome email
            try:
                msg = Message(
                    'Welcome to Crime Alert System',
                    recipients=[email],
                    body=f'Welcome {username}! Thank you for registering with our Crime Alert System.'
                )
                mail.send(msg)
            except Exception as e:
                print(f"Error sending welcome email: {str(e)}")
                # Don't stop the registration process if email fails
                
            flash('Registration successful! You can now login with your credentials.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Registration error: {str(e)}")
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to home
    if current_user.is_authenticated:
        flash('You are already logged in.', 'info')
        return redirect(url_for('home'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False) == 'on'
        
        # Basic validation
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return redirect(url_for('login'))
            
        # Get user and check if they exist
        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Use the same message for both cases to prevent username enumeration
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
            
        # Check if user is blocked
        if hasattr(user, 'is_blocked') and user.is_blocked:
            flash('This account has been blocked. Please contact support.', 'error')
            return redirect(url_for('login'))
            
        # Verify password
        if not check_password_hash(user.password_hash, password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
            
        # Login successful
        login_user(user, remember=remember)
        if remember:
            # Set permanent session
            session.permanent = True
            
        # Get the next page from the URL parameters
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('home')
            
        flash('Logged in successfully!', 'success')
        return redirect(next_page)
    
    return render_template('login.html')

@app.route('/verify_police_otp/<int:user_id>', methods=['GET', 'POST'])
def verify_police_otp(user_id):
    user = User.query.get(user_id)
    if request.method == 'POST':
        otp = request.form.get('otp')
        if otp is None:
            flash('No OTP entered. Please try again.')
            return redirect(url_for('verify_police_otp', user_id=user_id))
        
        otp = otp.strip()  # Trim any whitespace
        print(f"Entered OTP: {otp}, Stored OTP: {user.two_factor_code}")  # Debugging line
        if otp == user.two_factor_code:
            login_user(user)
            print(f"User {user.username} logged in successfully.")
            user.two_factor_code = None
            db.session.commit()
            
            # Check if the user is authenticated
            if current_user.is_authenticated:
                print("User is authenticated. Redirecting now.")
                return redirect(url_for('admin_dashboard'))
            else:
                print("User is not authenticated.")
        else:
            flash('Invalid OTP. Please try again.')

    return render_template('verify_police_otp.html', user=user)

@app.route('/resend_otp/<int:user_id>', methods=['POST'])
def resend_otp(user_id):
    user = User.query.get(user_id)
    if user:
        # Generate a new OTP
        user.two_factor_code = str(random.randint(100000, 999999))
        db.session.commit()

        # Send the new OTP via email
        msg = Message('Your OTP for Police Login', recipients=[user.email])
        msg.body = f'Your new OTP is: {user.two_factor_code}'
        mail.send(msg)

        flash('A new OTP has been sent to your email.')
    else:
        flash('User not found.')

    return redirect(url_for('verify_police_otp', user_id=user.id))

@app.route('/logout')
@login_required
def logout():
    # Clear the remember me cookie and session
    session.clear()
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('home'))

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report_crime():
    if request.method == 'POST':
        try:
            title = request.form['title']
            description = request.form['description']
            location = request.form['location']
            evidence = request.files['evidence']
            suspect_description = request.form.get('suspect_description')
            suspect_sketch_data = request.form.get('suspect_sketch')

            # Get latitude and longitude from form
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            
            # Get local timezone (default to Asia/Kolkata if not specified)
            local_tz = pytz.timezone('Asia/Kolkata')
            local_time = datetime.now(local_tz)
            
            # Check for duplicate reports in the last 5 minutes
            five_minutes_ago = local_time - timedelta(minutes=5)
            duplicate_reports = CrimeReport.query.filter(
                CrimeReport.user_id == current_user.id,
                CrimeReport.title == title,
                CrimeReport.location == location,
                CrimeReport.timestamp >= five_minutes_ago
            ).first()
            
            if duplicate_reports:
                flash('It appears you recently submitted a similar report. Please wait a few minutes before submitting again.', 'warning')
                return redirect(url_for('reports'))
            
            # Use reverse geocoding to get detailed location if not provided
            jurisdiction = None
            if not location and latitude and longitude:
                try:
                    geocoding_url = f"https://nominatim.openstreetmap.org/reverse?format=json&lat={latitude}&lon={longitude}"
                    response = requests.get(geocoding_url, headers={'User-Agent': 'OnAlert/1.0'})
                    if response.status_code == 200:
                        location_data = response.json()
                        address = location_data.get('address', {})
                        location = location_data.get('display_name', '').split(',')[0:3]
                        location = ', '.join(location)
                        # Get jurisdiction (city/district) for police assignment
                        jurisdiction = address.get('city', address.get('district', address.get('suburb')))
                        
                        # Try to get timezone from location
                        try:
                            lat, lon = float(latitude), float(longitude)
                            tf = timezonefinder.TimezoneFinder()
                            timezone_str = tf.timezone_at(lat=lat, lng=lon)
                            if timezone_str:
                                local_tz = pytz.timezone(timezone_str)
                                local_time = datetime.now(local_tz)
                        except Exception as e:
                            print(f"Error finding timezone: {str(e)}")
                            # Keep default timezone (Asia/Kolkata)
                            
                except Exception as e:
                    print(f"Error in reverse geocoding: {str(e)}")
                    # Fallback to coordinates if geocoding fails
                    location = f"Location at {latitude}, {longitude}"

            # Check if latitude and longitude are provided
            if not latitude or not longitude:
                flash('Please enable location services or select a location on the map.', 'danger')
                return redirect(url_for('report_crime'))

            # Evidence handling
            evidence_filename = None
            if evidence and evidence.filename:
                # Check file type
                allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx'}
                if '.' not in evidence.filename or \
                   evidence.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
                    flash('Invalid file type. Allowed types: PNG, JPG, JPEG, GIF, PDF, DOC, DOCX', 'danger')
                    return redirect(url_for('report_crime'))

                # Save the evidence file
                evidence_filename = secure_filename(evidence.filename)
                evidence_path = os.path.join(app.config['UPLOAD_FOLDER'], evidence_filename)
                evidence.save(evidence_path)

            # Handle suspect sketch if provided
            sketch_filename = None
            if suspect_sketch_data:
                try:
                    # Decode base64 image data
                    image_data = base64.b64decode(suspect_sketch_data.split(',')[1])
                    sketch_filename = f"sketch_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.png"
                    sketch_path = os.path.join(app.config['UPLOAD_FOLDER'], sketch_filename)
                    
                    # Save the sketch
                    with open(sketch_path, 'wb') as f:
                        f.write(image_data)
                except Exception as e:
                    flash('Error saving suspect sketch.', 'warning')
                    print(f"Error saving sketch: {str(e)}")

            # Create the crime report with local time
            report = CrimeReport(
                title=title,
                description=description,
                location=location,
                latitude=float(latitude),
                longitude=float(longitude),
                user_id=current_user.id,
                evidence_file=evidence_filename,
                suspect_description=suspect_description,
                suspect_sketch=sketch_filename,
                timestamp=local_time,
                status='pending'
            )

            db.session.add(report)
            db.session.commit()
            
            # Attempt to assign an available police officer
            if jurisdiction:
                available_officers = User.get_available_officers(jurisdiction)
                if available_officers:
                    assigned_officer = available_officers[0]  # Get the officer with the least cases
                    if assigned_officer.assign_case():
                        report.assigned_officer_id = assigned_officer.id
                        report.status = 'investigating'
                        db.session.commit()
                        
                        # Send notification to assigned officer
                        try:
                            msg = Message(
                                'New Crime Report Assigned',
                                recipients=[assigned_officer.email],
                                body=f'A new crime report has been assigned to you:\n\n'
                                     f'Title: {report.title}\n'
                                     f'Location: {report.location}\n'
                                     f'Description: {report.description}\n\n'
                                     f'Please log in to view the full details.'
                            )
                            mail.send(msg)
                        except Exception as e:
                            print(f"Error sending officer notification: {str(e)}")
            
            # Send confirmation email to the reporter
            try:
                msg = Message(
                    'Crime Report Confirmation',
                    recipients=[current_user.email],
                    body=f'Your crime report has been submitted successfully.\n\n'
                         f'Report Details:\n'
                         f'Title: {report.title}\n'
                         f'Location: {report.location}\n'
                         f'Status: {report.status.capitalize()}\n\n'
                         f'We will keep you updated on any progress.'
                )
                mail.send(msg)
            except Exception as e:
                print(f"Error sending confirmation email: {str(e)}")
            
            flash('Crime reported successfully', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while submitting the report. Please try again.', 'danger')
            print(f"Error submitting report: {str(e)}")
            return redirect(url_for('report_crime'))
        
    return render_template('report.html')

@app.route('/reports')
@app.route('/reports/<int:crime_id>')
def reports(crime_id=None):
    if current_user.is_authenticated:
        if current_user.is_police or current_user.is_admin:
            # Admin/Police can see all reports
            if crime_id:
                specific_report = CrimeReport.query.get_or_404(crime_id)
                reports = [specific_report] + CrimeReport.query.filter(CrimeReport.id != crime_id).order_by(CrimeReport.timestamp.desc()).all()
            else:
                reports = CrimeReport.query.order_by(CrimeReport.timestamp.desc()).all()
        else:
            # Regular users can only see their own reports
            if crime_id:
                specific_report = CrimeReport.query.filter_by(id=crime_id, user_id=current_user.id).first_or_404()
                reports = [specific_report] + CrimeReport.query.filter_by(user_id=current_user.id).filter(CrimeReport.id != crime_id).order_by(CrimeReport.timestamp.desc()).all()
            else:
                reports = CrimeReport.query.filter_by(user_id=current_user.id).order_by(CrimeReport.timestamp.desc()).all()
    else:
        # If not logged in, redirect to login page
        flash('Please login to view reports.', 'warning')
        return redirect(url_for('login'))
        
    return render_template('reports.html', reports=reports, focused_report_id=crime_id)

@app.route('/withdraw_report/<int:report_id>', methods=['POST'])
@login_required
def withdraw_report(report_id):
    """Allow a user to withdraw/delete their own report"""
    report = CrimeReport.query.get_or_404(report_id)
    
    # Security check - ensure the report belongs to the current user
    if report.user_id != current_user.id and not current_user.is_admin and not current_user.is_police:
        flash('You do not have permission to withdraw this report.', 'danger')
        return redirect(url_for('reports'))
    
    # Check if report can be withdrawn (only pending or investigating reports)
    if report.status not in ['pending', 'investigating']:
        flash('Reports that are resolved or closed cannot be withdrawn.', 'warning')
        return redirect(url_for('reports'))
    
    try:
        # For reports with evidence files or sketches, delete the files too
        if report.evidence_file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], report.evidence_file)
            if os.path.exists(file_path):
                os.remove(file_path)
                
        if report.suspect_sketch:
            sketch_path = os.path.join(app.config['UPLOAD_FOLDER'], report.suspect_sketch)
            if os.path.exists(sketch_path):
                os.remove(sketch_path)
        
        # Delete the report from the database
        db.session.delete(report)
        db.session.commit()
        
        flash('Your report has been successfully withdrawn.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while withdrawing the report: {str(e)}', 'danger')
    
    return redirect(url_for('reports'))

@app.route('/emergency-contacts', methods=['GET'])
@login_required
def emergency_contacts():
    """View emergency contacts for the current user."""
    contacts = EmergencyContact.query.filter_by(user_id=current_user.id).order_by(EmergencyContact.is_primary.desc()).all()
    return render_template('emergency_contacts.html', contacts=contacts)

@app.route('/emergency-contacts/add', methods=['POST'])
@login_required
def add_emergency_contact():
    """Add a new emergency contact."""
    data = request.get_json()
    name = data.get('name')
    phone = data.get('phone')
    relationship = data.get('relationship')
    is_primary = data.get('is_primary', False)
    
    if not name or not phone:
        return jsonify({'success': False, 'message': 'Name and phone are required'}), 400
        
    # Validate phone number format
    phone_pattern = re.compile(r'^\+?1?\d{9,15}$')
    if not phone_pattern.match(phone):
        return jsonify({'success': False, 'message': 'Invalid phone number format'}), 400
    
    try:
        # If this is a primary contact, update existing primary contacts
        if is_primary:
            EmergencyContact.query.filter_by(
                user_id=current_user.id, 
                is_primary=True
            ).update({'is_primary': False})
        
        contact = EmergencyContact(
            user_id=current_user.id,
            name=name,
            phone=phone,
            relationship=relationship,
            is_primary=is_primary
        )
        db.session.add(contact)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Contact added successfully',
            'contact': {
                'id': contact.id,
                'name': contact.name,
                'phone': contact.phone,
                'relationship': contact.relationship,
                'is_primary': contact.is_primary
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/emergency-contacts/<int:contact_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_emergency_contact(contact_id):
    """Update or delete an emergency contact."""
    contact = EmergencyContact.query.filter_by(
        id=contact_id, 
        user_id=current_user.id
    ).first_or_404()
    
    if request.method == 'DELETE':
        try:
            db.session.delete(contact)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Contact deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
    
    # PUT method
    data = request.get_json()
    try:
        if data.get('is_primary'):
            EmergencyContact.query.filter_by(
                user_id=current_user.id, 
                is_primary=True
            ).update({'is_primary': False})
        
        contact.name = data.get('name', contact.name)
        contact.phone = data.get('phone', contact.phone)
        contact.relationship = data.get('relationship', contact.relationship)
        contact.is_primary = data.get('is_primary', contact.is_primary)
        
        # Validate phone number if it's being updated
        if 'phone' in data:
            phone_pattern = re.compile(r'^\+?1?\d{9,15}$')
            if not phone_pattern.match(contact.phone):
                return jsonify({'success': False, 'message': 'Invalid phone number format'}), 400
        
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Contact updated successfully',
            'contact': {
                'id': contact.id,
                'name': contact.name,
                'phone': contact.phone,
                'relationship': contact.relationship,
                'is_primary': contact.is_primary
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/data')
@login_required
def data():
    if not current_user.is_police:
        flash('You do not have permission to access the analytics panel.', 'danger')
        return redirect(url_for('home'))
    
    # Basic statistics
    basic_stats = get_crime_statistics()
    
    # Time period for advanced analytics
    now = datetime.utcnow()
    last_year = now - timedelta(days=365)
    
    # ===== CRIME TYPE DISTRIBUTION =====
    crime_types = db.session.query(
        CrimeReport.title,
        func.count(CrimeReport.id).label('count')
    ).group_by(CrimeReport.title).all()
    
    crime_type_labels = [ct[0] for ct in crime_types]
    crime_type_data = [ct[1] for ct in crime_types]
    
    # ===== TIME-BASED ANALYSIS =====
    # Crime by hour of day
    hourly_crimes = db.session.query(
        func.extract('hour', CrimeReport.timestamp).label('hour'),
        func.count(CrimeReport.id).label('count')
    ).group_by('hour').order_by('hour').all()
    
    hourly_labels = [f"{int(h[0])}:00" for h in hourly_crimes]
    hourly_data = [h[1] for h in hourly_crimes]
    
    # Crime by day of week
    daily_crimes = db.session.query(
        func.extract('dow', CrimeReport.timestamp).label('day'),
        func.count(CrimeReport.id).label('count')
    ).group_by('day').order_by('day').all()
    
    day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    daily_labels = [day_names[int(d[0])] if d[0] is not None and 0 <= int(d[0]) < 7 else 'Unknown' for d in daily_crimes]
    daily_data = [d[1] for d in daily_crimes]
    
    # Crime by month (last 12 months)
    monthly_crimes = db.session.query(
        func.extract('month', CrimeReport.timestamp).label('month'),
        func.extract('year', CrimeReport.timestamp).label('year'),
        func.count(CrimeReport.id).label('count')
    ).filter(CrimeReport.timestamp >= last_year).group_by('month', 'year').order_by('year', 'month').all()
    
    month_names = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    monthly_labels = [f"{month_names[int(m[0])-1]} {int(m[1])}" if m[0] is not None and 1 <= int(m[0]) <= 12 else 'Unknown' for m in monthly_crimes]
    monthly_data = [m[2] for m in monthly_crimes]
    
    # ===== STATUS DISTRIBUTION =====
    status_distribution = db.session.query(
        CrimeReport.status,
        func.count(CrimeReport.id).label('count')
    ).group_by(CrimeReport.status).all()
    
    status_labels = [s[0].capitalize() for s in status_distribution]
    status_data = [s[1] for s in status_distribution]
    
    # ===== GEOGRAPHIC ANALYSIS =====
    # Top crime locations
    top_locations = db.session.query(
        CrimeReport.location,
        func.count(CrimeReport.id).label('count')
    ).group_by(CrimeReport.location).order_by(func.count(CrimeReport.id).desc()).limit(10).all()
    
    location_labels = [l[0] for l in top_locations]
    location_data = [l[1] for l in top_locations]
    
    # All crime coordinates for the map
    all_crimes = CrimeReport.query.order_by(CrimeReport.timestamp.desc()).all()
    map_data = [{
        'id': crime.id,
        'title': crime.title,
        'lat': crime.latitude,
        'lng': crime.longitude,
        'status': crime.status,
        'timestamp': crime.timestamp.strftime('%Y-%m-%d %H:%M'),
        'location': crime.location
    } for crime in all_crimes]
    
    # ===== PERFORMANCE METRICS =====
    # Average response times by crime type
    response_times = db.session.query(
        CrimeReport.title,
        func.avg(
            (func.julianday(CrimeReport.updated_at) - func.julianday(CrimeReport.timestamp)) * 24 * 60
        ).label('avg_mins')
    ).filter(
        CrimeReport.updated_at != None,
        CrimeReport.updated_at > CrimeReport.timestamp
    ).group_by(CrimeReport.title).all()
    
    response_time_labels = [r[0] for r in response_times]
    response_time_data = [round(r[1]) if r[1] is not None else 0 for r in response_times]
    
    # ===== RECENT ACTIVITY =====
    recent_updates = CrimeReport.query.filter(
        CrimeReport.updated_at >= (now - timedelta(days=7))
    ).order_by(CrimeReport.updated_at.desc()).limit(10).all()
    
    return render_template('data.html',
                         basic_stats=basic_stats,
                         crime_type_labels=crime_type_labels,
                         crime_type_data=crime_type_data,
                         hourly_labels=hourly_labels,
                         hourly_data=hourly_data,
                         daily_labels=daily_labels,
                         daily_data=daily_data,
                         monthly_labels=monthly_labels,
                         monthly_data=monthly_data,
                         status_labels=status_labels,
                         status_data=status_data,
                         location_labels=location_labels,
                         location_data=location_data,
                         map_data=map_data,
                         response_time_labels=response_time_labels,
                         response_time_data=response_time_data,
                         recent_updates=recent_updates)

@app.route('/crime/<int:crime_id>')
def view_crime(crime_id):
    crime = CrimeReport.query.get_or_404(crime_id)
    return render_template('view_crime.html', crime=crime)

@app.route('/download-emergency')
def download_emergency():
    return render_template('emergency.html')

@app.route('/download-emergency-pdf')
def download_emergency_pdf():
    # Create PDF with emergency contacts
    from fpdf import FPDF
    
    pdf = FPDF()
    pdf.add_page()
    
    # Add title
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Emergency Contact Numbers', 0, 1, 'C')
    
    # Add contacts
    pdf.set_font('Arial', '', 12)
    contacts = [
        ('Police Emergency', '100'),
        ('Fire Emergency', '101'),
        ('Ambulance', '102'),
        ('Women Helpline', '1091'),
        ('Child Helpline', '1098'),
        ('Anti-Corruption', '1031')
    ]
    
    for name, number in contacts:
        pdf.cell(0, 10, f'{name}: {number}', 0, 1)
    
    # Save PDF
    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'emergency_contacts.pdf')
    pdf.output(pdf_path)
    
    return send_file(pdf_path, as_attachment=True)

@app.route('/learn-first-aid')
def learn_first_aid():
    return render_template('first_aid.html')

@app.route('/download-first-aid-manual')
def download_first_aid_manual():
    manual_path = os.path.join(app.config['UPLOAD_FOLDER'], 'first_aid_manual.pdf')
    
    # Generate the PDF if it doesn't exist
    if not os.path.exists(manual_path):
        from fpdf import FPDF
        
        pdf = FPDF()
        pdf.add_page()
        
        # Add title
        pdf.set_font('Arial', 'B', 20)
        pdf.cell(0, 20, 'First Aid Manual', 0, 1, 'C')
        
        # Add subtitle
        pdf.set_font('Arial', 'I', 12)
        pdf.cell(0, 10, 'Emergency procedures everyone should know', 0, 1, 'C')
        pdf.ln(5)
        
        # Table of contents
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Contents:', 0, 1)
        pdf.ln(2)
        
        # CPR section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '1. CPR (Cardiopulmonary Resuscitation)', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Check if the person is unresponsive\n- Call emergency services (100 or 102)\n- Place hands in center of chest\n- Push hard and fast (100-120 compressions per minute)\n- Allow chest to fully recoil\n- If trained, give rescue breaths\n- Continue until help arrives or person shows signs of life')
        pdf.ln(5)
        
        # Bleeding control section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '2. Bleeding Control', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Ensure your safety (wear gloves if available)\n- Apply direct pressure with clean cloth or gauze\n- Maintain pressure for at least 15 minutes\n- If blood soaks through, add more cloth without removing first layer\n- Once bleeding slows, secure bandage firmly\n- Seek medical attention')
        pdf.ln(5)
        
        # Burns section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '3. Burns Treatment', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Run cool (not cold) water over the burn for 10-15 minutes\n- Do not apply ice, butter, or ointments\n- Cover with a sterile, non-stick bandage\n- Do not break blisters\n- Seek medical attention for serious burns')
        pdf.ln(5)
        
        # Choking section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '4. Choking Response', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Ask "Are you choking?"\n- Stand behind person and place one foot between their feet\n- Place fist above navel with thumb toward abdomen\n- Grasp fist with other hand and press inward and upward with quick thrusts\n- Repeat until object is expelled or medical help arrives')
        pdf.ln(5)
        
        # Fracture section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '5. Fracture Care', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Do not move the person unless necessary\n- Immobilize the injured area\n- Apply cold packs to reduce swelling\n- Treat for shock if necessary\n- Seek medical attention immediately')
        pdf.ln(5)
        
        # Snake bite section
        pdf.set_font('Arial', 'B', 14)
        pdf.cell(0, 10, '6. Snake Bite Treatment', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.multi_cell(0, 7, '- Keep the person calm and still\n- Remove jewelry and tight clothing\n- Position wound below heart level if possible\n- Clean wound gently with soap and water\n- Cover with clean, dry dressing\n- Mark the edge of swelling on the skin\n- Do NOT apply tourniquet, cut the wound, or try to suck out venom\n- Get medical help immediately')
        
        # Footer
        pdf.set_y(-30)
        pdf.set_font('Arial', 'I', 10)
        pdf.cell(0, 10, 'This guide is for informational purposes only and is not a substitute for professional medical advice.', 0, 1, 'C')
        pdf.cell(0, 10, 'In case of emergency, always call professionals: 100 (Police) or 102 (Ambulance)', 0, 1, 'C')
        
        # Save PDF
        pdf.output(manual_path)
    
    return send_file(manual_path, as_attachment=True)

@app.route('/nearby-hospitals')
def nearby_hospitals():
    # This would integrate with a maps API to show nearby hospitals
    # For now, redirect to a map view
    return render_template('nearby_hospitals.html')

@app.route('/training-courses')
def training_courses():
    # This would show available first aid training courses
    return render_template('training_courses.html')

@app.route('/join-watch')
def join_watch():
    # Get all unique areas from crime reports for the dropdown
    areas = db.session.query(CrimeReport.location).distinct().all()
    areas = [area[0] for area in areas]
    return render_template('neighborhood_watch.html', areas=areas)

@app.route('/register-watch', methods=['POST'])
def register_watch():
    if request.method == 'POST':
        member = WatchMember(
            name=request.form['name'],
            address=request.form['address'],
            phone=request.form['phone'],
            email=request.form['email'],
            area=request.form['area'],
            is_coordinator=bool(request.form.get('volunteer'))
        )
        db.session.add(member)
        db.session.commit()
        
        # Send welcome email
        msg = Message(
            'Welcome to Neighborhood Watch',
            recipients=[member.email],
            body=f'Thank you for joining the Neighborhood Watch program for {member.area}. '
                 f'We will keep you updated about community meetings and safety alerts.'
        )
        mail.send(msg)
        
        flash('Successfully registered for Neighborhood Watch!', 'success')
        return redirect(url_for('join_watch'))

@app.route('/get-meetings')
def get_meetings():
    meetings = CommunityMeeting.query.order_by(CommunityMeeting.date).all()
    return jsonify([{
        'title': m.title,
        'date': m.date.strftime('%B %d, %Y'),
        'time': m.time.strftime('%I:%M %p'),
        'location': m.location,
        'description': m.description
    } for m in meetings])

@app.route('/setup-alerts')
@login_required
def setup_alerts():
    # Load existing alert preferences for the user
    user_alert = UserAlert.query.filter_by(user_id=current_user.id).first()
    
    # If user has no preferences yet, create default values
    if not user_alert:
        user_alert = {
            'crime_alerts': True,
            'crime_radius': 2,
            'crime_frequency': 'daily',
            'community_alerts': True,
            'community_frequency': 'weekly',
            'meeting_reminders': True,
            'emergency_alerts': True,
            'alert_types': 'active_crime,severe_weather,missing_person,traffic',
            'emergency_location': current_user.jurisdiction or '',
            'notify_email': True,
            'notify_sms': False,
            'notify_app': True,
            'notification_sound': 'default',
            'silent_hours': False,
            'silent_start': '22:00',
            'silent_end': '07:00'
        }
    
    return render_template('setup_alerts.html', alert_prefs=user_alert)

@app.route('/save-alerts', methods=['POST'])
@login_required
def save_alerts():
    try:
        # Get form data
        crime_alerts = 'crime_alerts' in request.form
        crime_radius = request.form.get('crime_radius', 2)
        crime_frequency = request.form.get('crime_frequency', 'daily')
        community_alerts = 'community_alerts' in request.form
        community_frequency = request.form.get('community_frequency', 'weekly')
        meeting_reminders = 'meeting_reminders' in request.form
        emergency_alerts = 'emergency_alerts' in request.form
        
        # Handle multi-select values for alert types
        alert_types = request.form.getlist('alert_types')
        alert_types_str = ','.join(alert_types) if alert_types else 'active_crime,severe_weather'
        
        emergency_location = request.form.get('emergency_location', '')
        notify_email = 'notify_email' in request.form
        notify_sms = 'notify_sms' in request.form
        notify_app = 'notify_app' in request.form
        notification_sound = request.form.get('notification_sound', 'default')
        silent_hours = 'silent_hours' in request.form
        silent_start = request.form.get('silent_start', '22:00')
        silent_end = request.form.get('silent_end', '07:00')
        
        # Check if user already has alert preferences
        user_alert = UserAlert.query.filter_by(user_id=current_user.id).first()
        
        if user_alert:
            # Update existing record
            user_alert.crime_alerts = crime_alerts
            user_alert.crime_radius = crime_radius
            user_alert.crime_frequency = crime_frequency
            user_alert.community_alerts = community_alerts
            user_alert.community_frequency = community_frequency
            user_alert.meeting_reminders = meeting_reminders
            user_alert.emergency_alerts = emergency_alerts
            user_alert.alert_types = alert_types_str
            user_alert.emergency_location = emergency_location
            user_alert.notify_email = notify_email
            user_alert.notify_sms = notify_sms
            user_alert.notify_app = notify_app
            user_alert.notification_sound = notification_sound
            user_alert.silent_hours = silent_hours
            user_alert.silent_start = silent_start
            user_alert.silent_end = silent_end
            user_alert.updated_at = datetime.utcnow()
        else:
            # Create new record
            user_alert = UserAlert(
                user_id=current_user.id,
                crime_alerts=crime_alerts,
                crime_radius=crime_radius,
                crime_frequency=crime_frequency,
                community_alerts=community_alerts,
                community_frequency=community_frequency,
                meeting_reminders=meeting_reminders,
                emergency_alerts=emergency_alerts,
                alert_types=alert_types_str,
                emergency_location=emergency_location,
                notify_email=notify_email,
                notify_sms=notify_sms,
                notify_app=notify_app,
                notification_sound=notification_sound,
                silent_hours=silent_hours,
                silent_start=silent_start,
                silent_end=silent_end
            )
            db.session.add(user_alert)
        
        db.session.commit()
        
        # Log activity for debugging
        app.logger.info(f"Alert preferences saved for user {current_user.username}")
        
        # Update user phone if provided
        phone = request.form.get('phone')
        if phone and notify_sms:
            if not current_user.phone or current_user.phone != phone:
                current_user.phone = phone
                db.session.commit()
                app.logger.info(f"Updated phone number for user {current_user.username}")
        
        # Return success response
        return jsonify({
            'success': True,
            'message': 'Your alert preferences have been saved successfully!'
        })
        
    except Exception as e:
        app.logger.error(f"Error saving alert preferences: {str(e)}")
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': f'An error occurred: {str(e)}'
        }), 500

@app.route('/police')
def police_portal():
    """Direct path to police portal"""
    return redirect(url_for('police_login'))

@app.route('/police/login', methods=['GET', 'POST'])
def police_login():
    if current_user.is_authenticated and current_user.is_police:
        return redirect(url_for('admin_dashboard'))
    
    if current_user.is_authenticated:
        flash('You do not have permission to access the police panel.', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        jurisdiction = request.form.get('jurisdiction')
        
        user = User.query.filter_by(username=username).first()
        
        # Try both password checking methods
        password_valid = False
        if user:
            try:
                # First try the regular check_password method
                password_valid = user.check_password(password)
            except Exception:
                try:
                    # Then try using sha256_crypt directly
                    from passlib.hash import sha256_crypt
                    password_valid = sha256_crypt.verify(password, user.password_hash)
                except Exception:
                    password_valid = False
        
        if user and password_valid and user.is_police:
            # Update jurisdiction
            if jurisdiction:
                user.jurisdiction = jurisdiction
                db.session.commit()
                
            # Generate a random 6-digit OTP
            user.two_factor_code = str(random.randint(100000, 999999))
            db.session.commit()

            # Send the OTP via email
            msg = Message('Your OTP for Police Login', recipients=[user.email])
            msg.body = f'Your OTP is: {user.two_factor_code}'
            mail.send(msg)

            # Redirect to OTP verification page
            return redirect(url_for('verify_police_otp', user_id=user.id))
        else:
            flash('Authentication failed. Please check your credentials.', 'danger')
    
    return render_template('police_login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    return redirect(url_for('police_login'))

@app.route('/admin/dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.is_admin and not current_user.is_police:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('home'))
        
    # Get all reports, ordered by timestamp
    reports = CrimeReport.query.order_by(CrimeReport.timestamp.desc()).all()
    
    # Get statistics
    stats = get_crime_statistics()
    
    # Get unique locations from reports for filtering
    all_locations = [report.location for report in reports if report.location]
    
    # Add major Indian cities and states
    localities = sorted(set([
        'Delhi', 'Mumbai', 'Kolkata', 'Chennai', 'Bangalore', 'Hyderabad', 
        'Ahmedabad', 'Pune', 'Jaipur', 'Lucknow', 'Maharashtra', 
        'Tamil Nadu', 'Karnataka', 'Uttar Pradesh', 'Gujarat', 
        'Rajasthan', 'West Bengal', 'Bihar', 'Punjab'
    ] + all_locations))
    
    # Check if form was submitted
    if request.method == 'POST':
        # Get the selected locality from the form
        selected_locality = request.form.get('locality')
        # Only store in session if not empty
        if selected_locality:
            session['selected_locality'] = selected_locality
        else:
            # Clear the session if "All Localities" was selected
            session.pop('selected_locality', None)
    else:
        # For GET requests, use the session value
        selected_locality = session.get('selected_locality')
    
    # Get the selected status from the form or default to 'all'
    selected_status = request.form.get('status') or 'all'
    
    # Filter reports based on locality and status
    if selected_locality:
        reports = [r for r in reports if selected_locality.lower() in r.location.lower()]
    
    if selected_status != 'all':
        reports = [r for r in reports if r.status == selected_status]
    
    # ----- SIMPLIFIED ENQUIRIES LOGIC -----
    # Get ALL enquiries regardless of response status - for debugging
    unanswered_enquiries = ReportEnquiry.query.order_by(ReportEnquiry.created_at.desc()).all()
    
    # Debug info
    print(f"DEBUG: User {current_user.username}, Police: {current_user.is_police}, Admin: {current_user.is_admin}")
    print(f"DEBUG: Jurisdiction: {current_user.jurisdiction if hasattr(current_user, 'jurisdiction') else 'None'}")
    print(f"DEBUG: Total enquiries in DB: {ReportEnquiry.query.count()}")
    print(f"DEBUG: All enquiries retrieved: {len(unanswered_enquiries)}")
    
    # Print details of each enquiry for debugging
    for i, enq in enumerate(unanswered_enquiries):
        print(f"DEBUG: Enquiry {i+1}: ID={enq.id}, Report={enq.report_id}, User={enq.user_id}, Responded={enq.is_responded}")
    
    return render_template('admin_dashboard.html', 
                          reports=reports, 
                          statistics=stats, 
                          localities=localities,
                          selected_locality=selected_locality,
                          selected_status=selected_status,
                          unanswered_enquiries=unanswered_enquiries)

@app.route('/admin/update_report/<int:report_id>', methods=['GET', 'POST'])
@login_required
def update_report(report_id):
    if not current_user.is_police:
        flash('You do not have permission to access the police panel.', 'danger')
        return redirect(url_for('home'))
    
    report = CrimeReport.query.get_or_404(report_id)
    
    if request.method == 'POST':
        # Get officer's location from the form
        officer_location = request.form.get('officer_location')
    
        # Check if the report is in the officer's jurisdiction
        if current_user.jurisdiction and report.location.lower() != current_user.jurisdiction.lower():
            flash('You can only update reports in your jurisdiction.', 'danger')
            return redirect(url_for('admin_dashboard'))
        else:
            current_user.jurisdiction = officer_location
            db.session.commit()
    
        report.status = request.form.get('status')
        report.notes = request.form.get('notes')
        report.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Only try to send email if notify_user is checked
        if request.form.get('notify_user'):
            try:
                user = User.query.get(report.user_id)
                if not user:
                    print(f"User with ID {report.user_id} not found")
                    flash('User not found.', 'warning')
                    return redirect(url_for('admin_dashboard'))
                
                if not user.email:
                    print(f"User {user.username} has no email address")
                    flash('User has no email address.', 'warning')
                    return redirect(url_for('admin_dashboard'))
                
                print(f"Attempting to send email to: {user.email}")
                print(f"Using SMTP server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
                print(f"Using credentials: {app.config['MAIL_USERNAME']}")
                
                msg = Message(
                    subject='Your Crime Report Status Update',
                    recipients=[user.email],
                    body=f'Your report "{report.title}" has been updated to status: {report.status}.\n\nAdditional notes: {report.notes}'
                )
                mail.send(msg)
                
                print(f"Email sent successfully to {user.email}")
                flash('Report updated and email notification sent!', 'success')
            except Exception as e:
                error_msg = f"Error sending email: {str(e)}"
                print(error_msg)
                flash(f'Report updated but email notification failed: {error_msg}', 'warning')
                return redirect(url_for('admin_dashboard'))
        else:
            flash('Report updated successfully!', 'success')
        
        return redirect(url_for('admin_dashboard'))
    
    # For GET request, show the update form
    return render_template('update_report.html', report=report)

@app.route('/admin/verify_report/<int:report_id>', methods=['POST'])
@login_required
def verify_report(report_id):
    if not current_user.is_police:
        flash('You do not have permission to verify reports.', 'danger')
        return redirect(url_for('home'))
    
    report = CrimeReport.query.get_or_404(report_id)
    action = request.form.get('action')
    notes = request.form.get('notes')
    
    if action == 'verify':
        report.is_verified = True
        report.verification_status = 'verified'
        report.status = 'investigating'  # Update status when verified
        flash('Report has been verified.', 'success')
        
        # Send email notification to user
        if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
            try:
                user = User.query.get(report.user_id)
                msg = Message(
                    subject='Your Crime Report Has Been Verified',
                    recipients=[user.email],
                    body=f'Your report "{report.title}" has been verified and is now under investigation.\n\nNotes: {notes if notes else "No additional notes."}'
                )
                mail.send(msg)
            except Exception as e:
                flash('Report verified but email notification failed to send.', 'warning')
    
    elif action == 'mark_fake':
        report.is_verified = False
        report.verification_status = 'fake'
        report.status = 'closed'
        
        # Take action against user (e.g., flag their account)
        user = User.query.get(report.user_id)
        if user:
            if not hasattr(user, 'fake_reports_count'):
                user.fake_reports_count = 1
            else:
                user.fake_reports_count += 1
            
            if user.fake_reports_count >= 3:
                user.is_blocked = True
                report.action_taken = "User account blocked due to multiple fake reports"
            db.session.add(user)
            
            # Send email notification about fake report
            if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
                try:
                    msg = Message(
                        subject='Your Crime Report Has Been Marked as Fake',
                        recipients=[user.email],
                        body=f'Your report "{report.title}" has been marked as fake.\n\nNotes: {notes if notes else "No additional notes."}\n\nWarning: Multiple fake reports may result in account suspension.'
                    )
                    mail.send(msg)
                except Exception as e:
                    flash('Status updated but email notification failed to send.', 'warning')
        
        flash('Report has been marked as fake and appropriate action has been taken.', 'warning')
    
    report.notes = notes
    report.updated_at = datetime.utcnow()
    db.session.commit()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
@login_required
def admin_logout():
    if not current_user.is_police:
        return redirect(url_for('home'))
    logout_user()
    session.pop('is_police', None)
    session.pop('selected_locality', None)
    flash('You have been logged out from police panel', 'info')
    return redirect(url_for('home'))

@app.route('/download_evidence/<int:report_id>')
@login_required
def download_evidence(report_id):
    if not current_user.is_police and not current_user.is_admin:
        flash('You do not have permission to download evidence files.', 'danger')
        return redirect(url_for('home'))
        
    report = CrimeReport.query.get_or_404(report_id)
    file_type = request.args.get('type')
    as_attachment = request.args.get('download', 'false').lower() == 'true'
    
    # Handle suspect sketch
    if file_type == 'sketch' and report.suspect_sketch:
        try:
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                report.suspect_sketch,
                mimetype='image/png',
                as_attachment=as_attachment
            )
        except Exception as e:
            app.logger.error(f"Error downloading suspect sketch: {str(e)}")
            flash('Error downloading suspect sketch.', 'danger')
            return redirect(url_for('admin_dashboard'))
    
    # Handle evidence file
    if report.evidence_file:
        try:
            # Determine if it's an image for preview
            is_image = report.evidence_file.lower().endswith(('.png', '.jpg', '.jpeg', '.gif'))
            mimetype = None
            if is_image:
                # For images, set the proper mimetype for display
                ext = report.evidence_file.rsplit('.', 1)[1].lower()
                mimetype = f'image/{ext if ext != "jpg" else "jpeg"}'
            
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                report.evidence_file,
                mimetype=mimetype,
                as_attachment=as_attachment and not is_image
            )
        except Exception as e:
            app.logger.error(f"Error downloading evidence file: {str(e)}")
            flash('Error downloading evidence file.', 'danger')
            return redirect(url_for('admin_dashboard'))
            
    flash('No file available for this report.', 'warning')
    return redirect(url_for('admin_dashboard'))

@app.route('/test_email', methods=['GET'])
def test_email():
    """Route to test email functionality"""
    try:
        recipient_email = request.args.get('email', 'test@example.com')
        
        # Check if mail configuration is set up
        if not app.config['MAIL_USERNAME'] or not app.config['MAIL_PASSWORD']:
            return "Error: Mail username or password is not configured. Please check your .env file."
        
        # Debug information
        env_info = f"""
        Mail Configuration Debug:
        - Server: {app.config['MAIL_SERVER']}
        - Port: {app.config['MAIL_PORT']}
        - TLS Enabled: {app.config['MAIL_USE_TLS']}
        - Username: {app.config['MAIL_USERNAME']}
        - Password set: {bool(app.config['MAIL_PASSWORD'])}
        - Default sender: {app.config['MAIL_DEFAULT_SENDER']}
        """
        print(env_info)
        
        msg = Message(
            subject='Test Email from OnAlert',
            recipients=[recipient_email],
            body='This is a test email from the OnAlert system to verify email functionality is working.'
        )
        
        print(f"Attempting to send test email to: {recipient_email}")
        
        mail.send(msg)
        
        print("Test email sent successfully!")
        return f"Test email sent to {recipient_email}. Check your inbox and spam folder.<br><pre>{env_info}</pre>"
    
    except Exception as e:
        error_msg = f"Error sending test email: {str(e)}"
        print(error_msg)
        return f"Error sending email: {str(e)}<br><pre>{env_info if 'env_info' in locals() else 'Environment info not available'}</pre>"

@app.route('/fullmap')
@login_required
def fullmap():
    """Display a fullscreen interactive crime map for police officers."""
    # Only allow police officers to access this page
    if not current_user.is_police:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    
    # Get all crime reports
    reports = CrimeReport.query.all()
    
    return render_template('fullmap.html', reports=reports)

@app.route('/generate-sketch', methods=['POST'])
@login_required
def generate_sketch():
    try:
        # Get the description from the form
        description = request.form.get('description')
        
        # Get the Hugging Face token and check if it exists
        hf_token = os.getenv('HUGGINGFACE_TOKEN')
        print(f"HUGGINGFACE_TOKEN: {hf_token}")  # This will print the token or None if not set
        if not hf_token:
            print("Error: HUGGINGFACE_TOKEN not found in environment variables")
            return jsonify({
                'success': False,
                'error': 'API token not configured. Please contact the administrator.',
                'error_type': 'auth_error'
            })
            
        # Hugging Face API configuration - using a different model that's more stable
        API_URL = "https://api-inference.huggingface.co/models/CompVis/stable-diffusion-v1-4"
        headers = {"Authorization": f"Bearer {hf_token}"}
        
        try:
            # Print debug information
            print(f"Making request to Hugging Face API...")
            print(f"API URL: {API_URL}")
            print(f"Token (first 8 chars): {hf_token[:8]}...")
            
            # Prepare the prompt for the model
            prompt = f"police sketch of a suspect: {description}, realistic, detailed, forensic sketch style, black and white, pencil sketch"
            
            # Make request to Hugging Face API
            response = requests.post(
                API_URL,
                headers=headers,
                json={
                    "inputs": prompt,
                    "parameters": {
                        "negative_prompt": "color, blurry, unrealistic, cartoon, anime",
                        "num_inference_steps": 25,  # Reduced for better stability
                        "guidance_scale": 7.0,      # Slightly reduced for better stability
                        "width": 512,
                        "height": 512
                    }
                },
                timeout=30  # Add timeout to prevent hanging
            )
            
            # Print response status and headers for debugging
            print(f"Response status code: {response.status_code}")
            print(f"Response headers: {response.headers}")
            
            # Try to get more detailed error information
            try:
                response_json = response.json()
                print(f"Response content: {response_json}")
            except:
                print(f"Raw response content: {response.text}")
            
            # Check if the request was successful
            if response.status_code == 200:
                # Convert the image bytes to base64
                image_bytes = response.content
                img = Image.open(io.BytesIO(image_bytes))
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                img_str = base64.b64encode(buffered.getvalue()).decode()
                
                return jsonify({
                    'success': True,
                    'image': img_str
                })
            elif response.status_code == 503:
                print("Model is loading...")
                return jsonify({
                    'success': False,
                    'error': 'The image generation service is currently loading. Please try again in a few moments.',
                    'error_type': 'model_loading'
                })
            elif response.status_code == 401:
                print("Authentication failed. Token might be invalid or expired.")
                return jsonify({
                    'success': False,
                    'error': 'Authentication failed. Please check your API token.',
                    'error_type': 'auth_error'
                })
            elif response.status_code == 500:
                print("Server error occurred")
                error_message = "The image generation service encountered an error. "
                try:
                    error_details = response.json()
                    if 'error' in error_details:
                        error_message += str(error_details['error'])
                except:
                    error_message += "Please try again with a different description."
                
                return jsonify({
                    'success': False,
                    'error': error_message,
                    'error_type': 'server_error'
                })
            else:
                print(f"API request failed with status {response.status_code}")
                print(f"Response content: {response.text}")
                return jsonify({
                    'success': False,
                    'error': f'API request failed with status code: {response.status_code}',
                    'error_type': 'api_error'
                })
            
        except requests.exceptions.RequestException as api_error:
            print(f"Request exception: {str(api_error)}")
            return jsonify({
                'success': False,
                'error': f'Error communicating with the API: {str(api_error)}',
                'error_type': 'api_error'
            })
            
    except Exception as e:
        print(f"System error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'System error: {str(e)}',
            'error_type': 'system_error'
        })

@app.route('/debug')
def debug():
    return render_template('debug.html')
    
@app.route('/sos', methods=['GET', 'POST'])
@login_required
def sos():
    """SOS page where users can manage emergency contacts and view SOS history"""
    # Get user's emergency contacts
    emergency_contacts = EmergencyContact.query.filter_by(user_id=current_user.id).all()
    
    # Get user's SOS history
    sos_history = SOSAlert.query.filter_by(user_id=current_user.id).order_by(SOSAlert.timestamp.desc()).all()
    
    # For POST requests - adding a new emergency contact
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_contact':
            name = request.form.get('name')
            phone = request.form.get('phone')
            email = request.form.get('email')
            relationship = request.form.get('relationship')
            is_primary = request.form.get('is_primary') == 'on'
            
            # If this is a primary contact, unset any existing primary contacts
            if is_primary:
                primary_contacts = EmergencyContact.query.filter_by(user_id=current_user.id, is_primary=True).all()
                for contact in primary_contacts:
                    contact.is_primary = False
                    
            # Create new emergency contact
            contact = EmergencyContact(
                user_id=current_user.id,
                name=name,
                phone=phone,
                email=email,
                relationship=relationship,
                is_primary=is_primary
            )
            db.session.add(contact)
            db.session.commit()
            
            flash('Emergency contact added successfully!', 'success')
            return redirect(url_for('sos'))
            
    return render_template('sos.html', contacts=emergency_contacts, sos_history=sos_history)

@app.route('/delete_contact/<int:contact_id>', methods=['POST'])
@login_required
def delete_contact(contact_id):
    """Delete an emergency contact"""
    contact = EmergencyContact.query.get_or_404(contact_id)
    
    # Security check - ensure the contact belongs to the current user
    if contact.user_id != current_user.id:
        flash('You do not have permission to delete this contact.', 'danger')
        return redirect(url_for('sos'))
    
    db.session.delete(contact)
    db.session.commit()
    
    flash('Emergency contact deleted.', 'success')
    return redirect(url_for('sos'))

@app.route('/trigger_sos', methods=['POST'])
@login_required
def trigger_sos():
    """Trigger an SOS alert"""
    # Get location data from the request
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    location = request.form.get('location')
    message = request.form.get('message', 'I need help! This is an emergency!')
    
    # Create new SOS alert
    sos_alert = SOSAlert(
        user_id=current_user.id,
        location=location,
        latitude=latitude,
        longitude=longitude,
        message=message,
        status='active'
    )
    db.session.add(sos_alert)
    db.session.commit()
    
    # Send notifications to emergency contacts
    emergency_contacts = EmergencyContact.query.filter_by(user_id=current_user.id).all()
    for contact in emergency_contacts:
        try:
            # Send email notification
            if contact.email:
                msg = Message(
                    f'EMERGENCY: SOS Alert from {current_user.username}',
                    recipients=[contact.email]
                )
                msg.body = f'''
                EMERGENCY: {current_user.username} has triggered an SOS alert!
                
                Time: {sos_alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
                Location: {location if location else 'Unknown'}
                Coordinates: {latitude}, {longitude}
                Message: {message}
                
                Please take immediate action or contact emergency services!
                '''
                mail.send(msg)
        except Exception as e:
            print(f"Error sending notification to {contact.name}: {str(e)}")
    
    # Notify nearby police
    try:
        # Find police officers in the area
        nearby_police = User.query.filter(
            User.is_police == True,
            User.jurisdiction.ilike(f"%{location}%") if location else True
        ).all()
        
        # Send notifications to police
        for officer in nearby_police:
            if officer.email:
                msg = Message(
                    'EMERGENCY: SOS Alert Received',
                    recipients=[officer.email]
                )
                msg.body = f'''
                EMERGENCY SOS ALERT RECEIVED
                
                User: {current_user.username}
                Time: {sos_alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
                Location: {location if location else 'Unknown'}
                Coordinates: {latitude}, {longitude}
                Message: {message}
                
                Please check the police dashboard to respond.
                '''
                mail.send(msg)
    except Exception as e:
        print(f"Error notifying police: {str(e)}")
    
    # Return success response
    return jsonify({
        'success': True,
        'sos_id': sos_alert.id,
        'message': 'SOS alert has been triggered. Emergency contacts and authorities have been notified.'
    })

@app.route('/cancel_sos/<int:sos_id>', methods=['POST'])
@login_required
def cancel_sos(sos_id):
    """Cancel an active SOS alert"""
    sos_alert = SOSAlert.query.get_or_404(sos_id)
    
    # Security check - ensure the SOS alert belongs to the current user
    if sos_alert.user_id != current_user.id:
        flash('You do not have permission to cancel this SOS alert.', 'danger')
        return redirect(url_for('sos'))
    
    # Update SOS alert status
    sos_alert.status = 'resolved'
    sos_alert.resolved_at = datetime.utcnow()
    db.session.commit()
    
    # Notify emergency contacts and police that the alert has been cancelled
    try:
        # Notify contacts
        emergency_contacts = EmergencyContact.query.filter_by(user_id=current_user.id).all()
        for contact in emergency_contacts:
            if contact.email:
                msg = Message(
                    f'SOS Alert Cancelled: {current_user.username} is safe',
                    recipients=[contact.email]
                )
                msg.body = f'''
                {current_user.username} has cancelled their SOS alert.
                
                Time of cancellation: {sos_alert.resolved_at.strftime('%Y-%m-%d %H:%M:%S')}
                
                No further action is required.
                '''
                mail.send(msg)
    except Exception as e:
        print(f"Error sending cancellation notifications: {str(e)}")
    
    flash('SOS alert has been cancelled.', 'success')
    return redirect(url_for('sos'))

@app.route('/police/sos_alerts')
@login_required
def police_sos_alerts():
    """Show active SOS alerts for police officers"""
    if not current_user.is_police:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    
    # Get active SOS alerts, prioritizing those in the officer's jurisdiction
    if current_user.jurisdiction:
        # First get alerts from officer's jurisdiction
        jurisdiction_alerts = SOSAlert.query.join(User, SOSAlert.user_id == User.id)\
            .filter(SOSAlert.status == 'active', 
                    SOSAlert.location.ilike(f"%{current_user.jurisdiction}%"))\
            .order_by(SOSAlert.timestamp.desc()).all()
        
        # Then get other active alerts
        other_alerts = SOSAlert.query.filter(
            SOSAlert.status == 'active',
            ~SOSAlert.location.ilike(f"%{current_user.jurisdiction}%") if SOSAlert.location else True
        ).order_by(SOSAlert.timestamp.desc()).all()
        
        # Combine alerts
        sos_alerts = jurisdiction_alerts + other_alerts
    else:
        # If no jurisdiction set, get all active alerts
        sos_alerts = SOSAlert.query.filter_by(status='active').order_by(SOSAlert.timestamp.desc()).all()
    
    # Get resolved alerts
    resolved_alerts = SOSAlert.query.filter(
        SOSAlert.status.in_(['responded', 'resolved'])
    ).order_by(SOSAlert.timestamp.desc()).limit(20).all()
    
    return render_template('police_sos.html', active_alerts=sos_alerts, resolved_alerts=resolved_alerts, datetime=datetime)

@app.route('/police/respond_sos/<int:sos_id>', methods=['POST'])
@login_required
def respond_sos(sos_id):
    """Mark an SOS alert as being responded to"""
    if not current_user.is_police:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))
    
    sos_alert = SOSAlert.query.get_or_404(sos_id)
    
    # Update SOS alert
    sos_alert.status = 'responded'
    sos_alert.responder_id = current_user.id
    sos_alert.responder_notes = request.form.get('notes')
    db.session.commit()
    
    # Send notification to user that help is on the way
    try:
        user = User.query.get(sos_alert.user_id)
        if user and user.email:
            msg = Message(
                'Help is on the way - SOS Alert Response',
                recipients=[user.email]
            )
            msg.body = f'''
            Your SOS alert has been received and is being responded to.
            
            Officer: {current_user.username}
            Department: {current_user.department if current_user.department else 'Police Department'}
            Notes: {sos_alert.responder_notes if sos_alert.responder_notes else 'Help is on the way.'}
            
            Stay safe. Emergency services are being dispatched to your location.
            '''
            mail.send(msg)
    except Exception as e:
        print(f"Error sending response notification: {str(e)}")
    
    flash('SOS alert marked as being responded to.', 'success')
    return redirect(url_for('police_sos_alerts'))

@app.route('/police/resolve_sos/<int:sos_id>', methods=['POST'])
@login_required
def resolve_sos(sos_id):
    """Mark an SOS alert as resolved"""
    if not current_user.is_police:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('home'))
    
    sos_alert = SOSAlert.query.get_or_404(sos_id)
    
    # Update SOS alert
    sos_alert.status = 'resolved'
    sos_alert.resolved_at = datetime.utcnow()
    if request.form.get('notes'):
        sos_alert.responder_notes = request.form.get('notes')
    db.session.commit()
    
    flash('SOS alert marked as resolved.', 'success')
    return redirect(url_for('police_sos_alerts'))

@app.route('/api/police/check_new_alerts', methods=['GET'])
@login_required
def check_new_alerts():
    """API endpoint for checking if there are new SOS alerts"""
    if not current_user.is_police:
        return jsonify({'error': 'Unauthorized'}), 403
    
    # Get the timestamp of the last check from the query parameter
    last_check = request.args.get('last_check')
    if not last_check:
        return jsonify({'error': 'Missing last_check parameter'}), 400
    
    try:
        # Convert the timestamp to a datetime object
        last_check_dt = datetime.fromisoformat(last_check.replace('Z', '+00:00'))
        
        # Get alerts that were created after the last check
        if current_user.jurisdiction:
            # First check jurisdiction alerts
            new_jurisdiction_alerts = SOSAlert.query.filter(
                SOSAlert.timestamp > last_check_dt,
                SOSAlert.status == 'active',
                SOSAlert.location.ilike(f"%{current_user.jurisdiction}%")
            ).count()
            
            # Then check other alerts
            new_other_alerts = SOSAlert.query.filter(
                SOSAlert.timestamp > last_check_dt,
                SOSAlert.status == 'active',
                ~SOSAlert.location.ilike(f"%{current_user.jurisdiction}%") if SOSAlert.location else True
            ).count()
            
            new_alerts_count = new_jurisdiction_alerts + new_other_alerts
        else:
            # If no jurisdiction set, count all new active alerts
            new_alerts_count = SOSAlert.query.filter(
                SOSAlert.timestamp > last_check_dt,
                SOSAlert.status == 'active'
            ).count()
        
        # Get total active alerts count
        total_active_alerts = SOSAlert.query.filter_by(status='active').count()
        
        return jsonify({
            'new_alerts': new_alerts_count,
            'total_active_alerts': total_active_alerts,
            'last_check': datetime.utcnow().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/admin/add-meeting', methods=['GET', 'POST'])
@login_required
def add_community_meeting():
    if not current_user.is_police:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        try:
            # Parse date and time from form
            meeting_date = datetime.strptime(request.form.get('date'), '%Y-%m-%d').date()
            meeting_time = datetime.strptime(request.form.get('time'), '%H:%M').time()
            
            # Create new meeting
            meeting = CommunityMeeting(
                title=request.form.get('title'),
                date=meeting_date,
                time=meeting_time,
                location=request.form.get('location'),
                description=request.form.get('description', '')
            )
            db.session.add(meeting)
            db.session.commit()
            
            # Notify users who want meeting reminders
            notify_users_about_meeting(meeting)
            
            flash('Meeting added successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding meeting: {str(e)}', 'danger')
    
    return render_template('add_meeting.html')

def notify_users_about_meeting(meeting):
    """Send notifications to users who have requested meeting reminders"""
    try:
        # Find all users with meeting reminders enabled
        alerts = UserAlert.query.filter_by(meeting_reminders=True).all()
        
        if not alerts:
            return
        
        # Get user IDs to notify
        user_ids = [alert.user_id for alert in alerts]
        
        # Get users with those IDs
        users = User.query.filter(User.id.in_(user_ids)).all()
        
        # Send email notifications
        for user in users:
            # Check if user wants email notifications
            user_alert = next((a for a in alerts if a.user_id == user.id), None)
            if user_alert and user_alert.notify_email and user.email:
                msg = Message(
                    subject=f'New Community Meeting: {meeting.title}',
                    recipients=[user.email],
                    body=f"""
A new neighborhood watch meeting has been scheduled:

Title: {meeting.title}
Date: {meeting.date.strftime('%B %d, %Y')}
Time: {meeting.time.strftime('%I:%M %p')}
Location: {meeting.location}

{meeting.description}

Thank you for being part of our neighborhood watch program.
                    """
                )
                mail.send(msg)
    except Exception as e:
        app.logger.error(f"Error notifying users about meeting: {str(e)}")

@app.route('/report_enquiry/<int:report_id>', methods=['POST'])
@login_required
def submit_enquiry(report_id):
    """Submit an enquiry about a report"""
    report = CrimeReport.query.get_or_404(report_id)
    
    # Security check - ensure the user is authorized to enquire about this report
    if report.user_id != current_user.id and not current_user.is_admin and not current_user.is_police:
        flash('You do not have permission to enquire about this report.', 'danger')
        return redirect(url_for('reports'))
    
    message = request.form.get('enquiry_message')
    if not message or len(message.strip()) == 0:
        flash('Please enter a valid enquiry message.', 'warning')
        return redirect(url_for('reports', crime_id=report_id))
    
    try:
        # Create the enquiry with explicit timestamps
        enquiry = ReportEnquiry(
            report_id=report_id,
            user_id=current_user.id,
            message=message,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        db.session.add(enquiry)
        db.session.commit()
        
        # Notify police officers assigned to the jurisdiction about the new enquiry
        if report.jurisdiction:
            officers = User.query.filter_by(is_police=True, jurisdiction=report.jurisdiction).all()
            for officer in officers:
                if officer.email:
                    try:
                        msg = Message(
                            subject='New Enquiry for Crime Report',
                            recipients=[officer.email],
                            body=f"""
A new enquiry has been submitted for crime report #{report.id}: {report.title}

From: {current_user.username}
Message: {message}

You can respond to this enquiry from the police dashboard.
"""
                        )
                        mail.send(msg)
                    except Exception as e:
                        app.logger.error(f"Failed to send email notification to officer {officer.id}: {str(e)}")
        
        flash('Your enquiry has been submitted successfully. You will be notified when there is a response.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while submitting your enquiry: {str(e)}', 'danger')
    
    return redirect(url_for('reports', crime_id=report_id))

@app.route('/report_enquiries/<int:report_id>')
@login_required
def view_enquiries(report_id):
    """View all enquiries for a report"""
    report = CrimeReport.query.get_or_404(report_id)
    
    # Security check - ensure the user is authorized to view enquiries for this report
    if report.user_id != current_user.id and not current_user.is_admin and not current_user.is_police:
        flash('You do not have permission to view enquiries for this report.', 'danger')
        return redirect(url_for('reports'))
    
    enquiries = ReportEnquiry.query.filter_by(report_id=report_id).order_by(ReportEnquiry.created_at.desc()).all()
    
    # Fix any future dates by setting them to current time
    current_time = datetime.now()
    for enquiry in enquiries:
        if enquiry.created_at.year > 2023:
            enquiry.created_at = current_time - timedelta(minutes=30)  # 30 minutes ago
        if enquiry.updated_at and enquiry.updated_at.year > 2023:
            enquiry.updated_at = current_time
    
    return render_template('report_enquiries.html', report=report, enquiries=enquiries)

@app.route('/respond_enquiry/<int:enquiry_id>', methods=['POST'])
@login_required
def respond_enquiry(enquiry_id):
    """Respond to an enquiry (police/admin only)"""
    if not current_user.is_police and not current_user.is_admin:
        flash('You do not have permission to respond to enquiries.', 'danger')
        return redirect(url_for('reports'))
    
    enquiry = ReportEnquiry.query.get_or_404(enquiry_id)
    report = enquiry.report
    
    # If it's a police officer, check if they have jurisdiction
    if current_user.is_police and not current_user.is_admin:
        if current_user.jurisdiction and report.location.lower() != current_user.jurisdiction.lower():
            flash('You can only respond to enquiries for reports in your jurisdiction.', 'danger')
            return redirect(url_for('admin_dashboard'))
    
    response = request.form.get('response')
    if not response or len(response.strip()) == 0:
        flash('Please enter a valid response.', 'warning')
        return redirect(url_for('view_enquiries', report_id=report.id))
    
    try:
        # Update the enquiry with response and current timestamp
        enquiry.response = response
        enquiry.is_responded = True
        enquiry.updated_at = datetime.now()
        db.session.commit()
        
        # Notify the user who submitted the enquiry
        user = User.query.get(enquiry.user_id)
        if user and user.email:
            try:
                msg = Message(
                    subject='Response to Your Crime Report Enquiry',
                    recipients=[user.email],
                    body=f"""
Your enquiry about crime report #{report.id}: {report.title} has received a response:

Your enquiry: {enquiry.message}

Response: {response}

You can view all communications about this report on the reports page.
"""
                )
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Failed to send email notification to user {user.id}: {str(e)}")
        
        flash('Your response has been submitted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while submitting your response: {str(e)}', 'danger')
    
    return redirect(url_for('view_enquiries', report_id=report.id))

if __name__ == '__main__':
    with app.app_context():
        # Only create tables if they don't exist, don't drop them
        db.create_all()
        
        # Create police officer account if it doesn't exist
        police_officer = User.query.filter_by(username='police').first()
        email_exists = User.query.filter_by(email='police@example.com').first()
        
        if not police_officer and not email_exists:
            # Check if badge number already exists
            existing_badge = User.query.filter_by(badge_number='PD12345').first()
            if existing_badge:
                badge_number = f'PD{random.randint(10000, 99999)}'
                print(f"Badge number PD12345 already exists, using {badge_number} instead")
            else:
                badge_number = 'PD12345'
                
            police_officer = User(
                username='police',
                email='police@example.com',
                password_hash=sha256_crypt.hash('police123'),
                is_admin=True,
                is_police=True,
                badge_number=badge_number,
                department='City Police Department',
                rank='Officer',
                jurisdiction='Delhi'
            )
            db.session.add(police_officer)
            db.session.commit()
            print("Police officer account created successfully!")
            
            # Add sample crime reports only if this is a fresh installation
            sample_reports = [
                # Mumbai
                {'title': 'Theft at Colaba', 'location': 'Colaba, Mumbai', 'lat': 18.9067, 'lng': 72.8147},
                {'title': 'Vehicle Break-in', 'location': 'Bandra West, Mumbai', 'lat': 19.0596, 'lng': 72.8295},
                {'title': 'Robbery Incident', 'location': 'Andheri East, Mumbai', 'lat': 19.1136, 'lng': 72.8697},
                
                # Delhi
                {'title': 'Phone Snatching', 'location': 'Connaught Place, Delhi', 'lat': 28.6289, 'lng': 77.2065},
                {'title': 'Shop Burglary', 'location': 'Karol Bagh, Delhi', 'lat': 28.6449, 'lng': 77.1906},
                {'title': 'Assault Case', 'location': 'Lajpat Nagar, Delhi', 'lat': 28.5700, 'lng': 77.2373},
                
                # Bangalore
                {'title': 'Cyber Crime', 'location': 'Koramangala, Bangalore', 'lat': 12.9279, 'lng': 77.6271},
                {'title': 'Vehicle Theft', 'location': 'Indiranagar, Bangalore', 'lat': 12.9719, 'lng': 77.6412},
                {'title': 'Fraud Report', 'location': 'Whitefield, Bangalore', 'lat': 12.9698, 'lng': 77.7499},
                
                # Chennai
                {'title': 'Property Damage', 'location': 'T Nagar, Chennai', 'lat': 13.0418, 'lng': 80.2341},
                {'title': 'Harassment Case', 'location': 'Adyar, Chennai', 'lat': 13.0012, 'lng': 80.2565},
                {'title': 'Missing Person', 'location': 'Anna Nagar, Chennai', 'lat': 13.0850, 'lng': 80.2101},
                
                # Kolkata
                {'title': 'Street Fight', 'location': 'Park Street, Kolkata', 'lat': 22.5515, 'lng': 88.3476},
                {'title': 'Vandalism', 'location': 'Salt Lake City, Kolkata', 'lat': 22.5689, 'lng': 88.4140},
                {'title': 'Drug Related', 'location': 'Howrah, Kolkata', 'lat': 22.5958, 'lng': 88.2636},
                
                # Hyderabad
                {'title': 'Online Scam', 'location': 'Hitech City, Hyderabad', 'lat': 17.4435, 'lng': 78.3772},
                {'title': 'Chain Snatching', 'location': 'Banjara Hills, Hyderabad', 'lat': 17.4156, 'lng': 78.4347},
                {'title': 'ATM Fraud', 'location': 'Secunderabad, Hyderabad', 'lat': 17.4399, 'lng': 78.4983},
                
                # Pune
                {'title': 'Bike Theft', 'location': 'Koregaon Park, Pune', 'lat': 18.5362, 'lng': 73.8940},
                {'title': 'House Break-in', 'location': 'Kothrud, Pune', 'lat': 18.5074, 'lng': 73.8077},
                {'title': 'Cyberbullying', 'location': 'Hinjewadi, Pune', 'lat': 18.5913, 'lng': 73.7389},
                
                # Ahmedabad
                {'title': 'Shop Lifting', 'location': 'Navrangpura, Ahmedabad', 'lat': 23.0225, 'lng': 72.5714},
                {'title': 'Credit Card Fraud', 'location': 'Satellite, Ahmedabad', 'lat': 23.0128, 'lng': 72.5289},
                {'title': 'Identity Theft', 'location': 'Prahlad Nagar, Ahmedabad', 'lat': 23.0121, 'lng': 72.5097},
                
                # Jaipur
                {'title': 'Tourist Scam', 'location': 'Pink City, Jaipur', 'lat': 26.9124, 'lng': 75.7873},
                {'title': 'Jewelry Theft', 'location': 'Malviya Nagar, Jaipur', 'lat': 26.8570, 'lng': 75.8245},
                {'title': 'Hotel Robbery', 'location': 'C Scheme, Jaipur', 'lat': 26.9115, 'lng': 75.7921}
            ]
            
            for report_data in sample_reports:
                report = CrimeReport(
                    title=report_data['title'],
                    description=f"Sample crime report for {report_data['location']}",
                    location=report_data['location'],
                    latitude=report_data['lat'],
                    longitude=report_data['lng'],
                    user_id=police_officer.id,
                    status=random.choice(['pending', 'investigating', 'resolved']),
                    timestamp=datetime.utcnow() - timedelta(days=random.randint(0, 30))
                )
                db.session.add(report)
            
            db.session.commit()
            print("Sample crime reports added successfully!")
        else:
            if police_officer:
                print("Police officer account already exists!")
            else:
                print("Email 'police@example.com' is already in use by another account!")
            
        # Create a test enquiry if none exist
        enquiry_count = ReportEnquiry.query.count()
        if enquiry_count == 0:
            # Find a report to attach the enquiry to
            report = CrimeReport.query.first()
            if report:
                # Find a user to be the author of the enquiry
                user = User.query.first()
                if user:
                    test_enquiry = ReportEnquiry(
                        report_id=report.id,
                        user_id=user.id,
                        message="This is a test enquiry. Please respond when you see this message.",
                        is_responded=False,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(test_enquiry)
                    db.session.commit()
                    print(f"Created test enquiry for report #{report.id} from user {user.username}")
            
    app.run(debug=True)
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Keep sessions for 7 days
