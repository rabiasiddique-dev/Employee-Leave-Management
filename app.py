import os
from flask import Flask, g, render_template, request, redirect, url_for, session, flash, jsonify, Response
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps
import click
from flask.cli import with_appcontext
import logging
import secrets # For generating secure tokens

# --- Timezone Handling ---
import pytz
# --- End Timezone Handling ---

# --- CSV Export Imports ---
import csv
from io import StringIO
# --- End CSV Export Imports ---

# --- Email Imports ---
from flask_mail import Mail, Message
# --- End Email Imports ---

# --- WTForms Imports ---
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional
# --- End WTForms Imports ---

# --- Pagination Import ---
from flask_paginate import Pagination, get_page_parameter

# Load environment variables
load_dotenv()

# ########################################################################### #
# #                            APP INITIALIZATION                             #
# ########################################################################### #

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'a_default_secret_key_for_development')
app.config['WTF_CSRF_ENABLED'] = True

# Make datetime object available globally in Jinja2 templates
app.jinja_env.globals.update(datetime=datetime)


# --- Application Constants ---
LOCAL_TIMEZONE_STR = os.getenv('LOCAL_TIMEZONE', 'Asia/Karachi')
try:
    LOCAL_TIMEZONE = pytz.timezone(LOCAL_TIMEZONE_STR)
except pytz.exceptions.UnknownTimeZoneError:
    print(f"WARNING: Unknown timezone '{LOCAL_TIMEZONE_STR}'. Defaulting to UTC.")
    LOCAL_TIMEZONE = pytz.utc
# --- End Application Constants ---


# --- Email Configuration ---
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config.get('MAIL_USERNAME', 'noreply@example.com'))
app.config['MAIL_DEFAULT_SENDER_NAME'] = os.getenv('MAIL_DEFAULT_SENDER_NAME', 'LeaveFlow System')

mail = Mail(app)
if app.debug:
    app.logger.setLevel(logging.DEBUG)
    app.config['MAIL_DEBUG'] = True
else:
    app.logger.setLevel(logging.INFO)
app.logger.info("Flask App Initialized with Email Configuration.")
# --- End Email Configuration ---

# --- MongoDB Configuration ---
MONGO_URI = os.getenv('MONGO_URI')
if not MONGO_URI:
    app.logger.critical("FATAL ERROR: MONGO_URI not found.")
    exit()
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command('ping')
    app.logger.info("Successfully connected to MongoDB.")
    db_name_part = MONGO_URI.split('/')[-1]
    DB_NAME = db_name_part.split('?')[0] if '?' in db_name_part else db_name_part
    if not DB_NAME:
        app.logger.critical("FATAL ERROR: Could not determine Database Name from MONGO_URI.")
        exit()
    db = client[DB_NAME]
    app.logger.info(f"Using database: {DB_NAME}")

    # Ensure counters collection exists and has an employeeId sequence
    try:
        if db.counters.find_one({"_id": "employeeId"}) is None:
            db.counters.insert_one({"_id": "employeeId", "seq": 0})
            app.logger.info("Initialized 'employeeId' sequence in counters collection.")
    except Exception as e:
        app.logger.error(f"Error initializing counters collection: {e}", exc_info=True)


except Exception as e:
    app.logger.critical(f"MongoDB connection failed: {e}", exc_info=True)
    exit()
users_collection = db.users
leaves_collection = db.leaves
notifications_collection = db.notifications
settings_collection = db.settings
holidays_collection = db.holidays
# Counters collection for generating memorable IDs
counters_collection = db.counters
# Collection for password reset tokens
reset_tokens_collection = db.reset_tokens
app.logger.info("Database collections initialized.")
# --- End MongoDB Configuration ---

# ########################################################################### #
# #                       GLOBAL CONTEXT & BEFORE REQUEST                     #
# ########################################################################### #
@app.before_request
def before_request():
    """Ran before each request."""
    # Set current year on Flask's global object 'g'
    g.current_year = datetime.utcnow().year

# ########################################################################### #
# #                           JINJA2 CUSTOM FILTERS                           #
# ########################################################################### #
import calendar
def month_name_filter(month_number):
    try: return calendar.month_name[int(month_number)]
    except (ValueError, IndexError): return str(month_number)
app.jinja_env.filters['month_name'] = month_name_filter

def format_datetime_local(dt_obj, format_str='%d-%b-%Y %I:%M %p'):
    if not dt_obj: return "N/A"

    # If the object is a string, try to parse it into a datetime object first
    if isinstance(dt_obj, str):
        try:
            # Handle 'Z' suffix for UTC and then localize (fromisoformat handles Z directly in Python 3.11+)
            # For older Python, replace 'Z' with '+00:00'
            dt_obj_str = dt_obj.replace("Z", "+00:00")
            dt_obj = datetime.fromisoformat(dt_obj_str)
            # If timezone info is missing after fromisoformat, assume UTC
            if dt_obj.tzinfo is None or dt_obj.tzinfo.utcoffset(dt_obj) is None:
                dt_obj = pytz.utc.localize(dt_obj)
        except ValueError:
            # Fallback for other common string formats if fromisoformat fails
            try:
                # Try common MongoDB string format without explicit timezone
                dt_obj = datetime.strptime(dt_obj, '%Y-%m-%dT%H:%M:%S.%f')
                dt_obj = pytz.utc.localize(dt_obj) # Assume UTC if no tzinfo
            except ValueError:
                try: # Another common format
                    dt_obj = datetime.strptime(dt_obj, '%Y-%m-%d %H:%M:%S.%f')
                    dt_obj = pytz.utc.localize(dt_obj) # Assume UTC if no tzinfo
                except ValueError:
                    return str(dt_obj) # Return original string if all parsing fails

    # Ensure it's a datetime object before attempting timezone conversion
    if isinstance(dt_obj, datetime):
        # If the datetime object is already timezone-aware
        if dt_obj.tzinfo is not None and dt_obj.tzinfo.utcoffset(dt_obj) is not None:
            try:
                return dt_obj.astimezone(LOCAL_TIMEZONE).strftime(format_str)
            except Exception as e:
                # Fallback if astimezone fails for some reason
                app.logger.error(f"Error converting timezone for {dt_obj}: {e}")
                return dt_obj.strftime(format_str) # Fallback to naive UTC format
        else:
            # Naive datetime object: assume UTC and convert
            try:
                aware_utc_dt = pytz.utc.localize(dt_obj)
                return aware_utc_dt.astimezone(LOCAL_TIMEZONE).strftime(format_str)
            except Exception as e_utc:
                app.logger.error(f"Error localizing naive datetime {dt_obj}: {e_utc}")
                return dt_obj.strftime(format_str) # Fallback if localization fails
    else:
        return str(dt_obj) # Should not happen if previous checks pass, but for safety
app.jinja_env.filters['datetime_local'] = format_datetime_local

@app.template_filter('truncate')
def truncate_filter(s, length=255, killwords=False):
    if not isinstance(s, str):
        return str(s) # Ensure it's a string
    if len(s) <= length:
        return s
    if killwords:
        return s[:length].strip() + '...'
    words = s.split(' ')
    out = []
    for word in words:
        # Check if adding the next word exceeds the length
        if len(' '.join(out) + (' ' if out else '') + word) > length:
            break
        out.append(word)
    return ' '.join(out).strip() + '...'
app.jinja_env.filters['truncate'] = truncate_filter

@app.template_filter('display_status_text')
def display_status_text_filter(status_string):
    """Formats the leave status for display."""
    if not isinstance(status_string, str):
        return str(status_string)

    # Specific remapping for 'Cancelled (Approved Leave)' and 'Cancelled by User'
    if status_string.lower() == 'cancelled (approved leave)' or status_string.lower() == 'cancelled by user':
        return 'Cancelled' # Always display as 'Cancelled'

    # For other statuses, just title case them
    return status_string.title()
app.jinja_env.filters['display_status_text'] = display_status_text_filter

# --- End Jinja2 Custom Filters ---

# ########################################################################### #
# #                              HELPER FUNCTIONS                             #
# ########################################################################### #

def serialize_mongo_data(data):
    if isinstance(data, list): return [serialize_mongo_data(item) for item in data]
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, ObjectId): data[key] = str(value)
            elif isinstance(value, datetime): data[key] = value.isoformat()
            elif isinstance(value, (dict, list)): data[key] = serialize_mongo_data(value)
    return data

def hash_password(password_string):
    return bcrypt.hashpw(password_string.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_password, user_password_string):
    return bcrypt.checkpw(user_password_string.encode('utf-8'), hashed_password)

def create_notification(recipient_id, recipient_type, message, link=None, related_id=None, related_type=None):
    if not isinstance(message, str): message = str(message)
    # Store UTC timezone-aware datetime
    utc_now = pytz.utc.localize(datetime.utcnow())
    notification_doc = {
        "recipient_id": recipient_id,
        "recipient_type": recipient_type,
        "message": message,
        "link": link,
        "is_read": False,
        "created_at": utc_now,
        "related_id": related_id, # New field for associating with a leave, etc.
        "related_type": related_type # New field, e.g., 'leave_application'
    }
    try:
        notifications_collection.insert_one(notification_doc)
        app.logger.info(f"In-app notification created for {recipient_type} (ID: {recipient_id if recipient_id else 'ALL ADMINS'}).")
    except Exception as e: app.logger.error(f"Error creating in-app notification: {e}", exc_info=True)

def send_email_notification(recipient_email, subject, html_body):
    if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
        app.logger.warning("Email not sent: MAIL_USERNAME or MAIL_PASSWORD not configured.")
        return False
    if not recipient_email:
        app.logger.warning("Email not sent: Recipient email is missing.")
        return False
    recipients_list = [recipient_email] if isinstance(recipient_email, str) else list(recipient_email)
    valid_recipients = [email.strip() for email in recipients_list if email and email.strip() and "@" in email]
    if not valid_recipients:
        app.logger.warning("Email not sent: No valid recipient emails provided.")
        return False
    sender_email = app.config['MAIL_DEFAULT_SENDER']
    sender_name = app.config.get('MAIL_DEFAULT_SENDER_NAME')
    msg_sender = (sender_name, sender_email) if sender_name and sender_name.strip() else sender_email
    msg = Message(subject, sender=msg_sender, recipients=valid_recipients)
    msg.html = html_body
    try:
        with app.app_context(): mail.send(msg)
        app.logger.info(f"Email sent to: {', '.join(valid_recipients)} with sender: {msg_sender}")
        return True
    except Exception as e:
        app.logger.error(f"Error sending email to {', '.join(valid_recipients)}: {e}", exc_info=True)
        return False

# Helper for generating sequential employee codes
def get_next_sequence(name):
    """Increments and returns the next sequence number for a given counter name."""
    sequence_doc = counters_collection.find_one_and_update(
        {'_id': name},
        {'$inc': {'seq': 1}},
        return_document=True, # Return the updated document
        upsert=True # Create the document if it doesn't exist
    )
    return sequence_doc['seq']

# UPDATED: Validation helper for employee data
def validate_employee_data(data, is_new_employee=True, current_employee_id=None):
    errors = {}

    # Name validation
    name = data.get('name')
    if is_new_employee: # For new employee, name is always required
        if not name or not name.strip():
            errors['name'] = 'Name is required.'
    elif name is not None: # For existing employee, if name is provided, it must not be empty
        if not name.strip():
            errors['name'] = 'Name cannot be empty.'

    # Email validation
    email = data.get('email')
    if is_new_employee: # For new employee, email is always required
        email_stripped = email.strip().lower() if email else ''
        if not email_stripped:
            errors['email'] = 'Email is required.'
        elif not "@" in email_stripped or not "." in email_stripped:
            errors['email'] = 'Invalid email format.'
        else:
            # Check for email uniqueness
            query = {'email': email_stripped}
            if not is_new_employee and current_employee_id:
                query['_id'] = {'$ne': current_employee_id}
            if users_collection.find_one(query):
                errors['email'] = 'This email address is already in use.'
    elif email is not None: # For existing employee, if email is provided, validate it
        email_stripped = email.strip().lower() if email else ''
        if not email_stripped:
            errors['email'] = 'Email cannot be empty.'
        elif not "@" in email_stripped or not "." in email_stripped:
            errors['email'] = 'Invalid email format.'
        else:
            query = {'email': email_stripped}
            if current_employee_id:
                query['_id'] = {'$ne': current_employee_id}
            if users_collection.find_one(query):
                errors['email'] = 'This email address is already in use.'

    # Employee ID validation (user-provided ID)
    employee_id = data.get('employee_id')
    if is_new_employee: # For new employee, employee_id is always required
        if not employee_id or not employee_id.strip():
            errors['employee_id'] = 'Employee ID is required.'
        else:
            query = {'employee_id': employee_id.strip()}
            if users_collection.find_one(query):
                errors['employee_id'] = 'This employee ID is already in use.'
    elif employee_id is not None: # For existing employee, if employee_id is provided, validate it
        if not employee_id.strip():
            errors['employee_id'] = 'Employee ID cannot be empty.'
        else:
            query = {'employee_id': employee_id.strip()}
            if current_employee_id:
                query['_id'] = {'$ne': current_employee_id}
            if users_collection.find_one(query):
                errors['employee_id'] = 'This employee ID is already in use.'

    # Password validation (only required for new employees, or if provided for update)
    password = data.get('password')
    if is_new_employee:
        if not password or not password.strip():
            errors['password'] = 'Password is required for new employees.'
        elif len(password.strip()) < 6:
            errors['password'] = 'Password must be at least 6 characters long.'
    elif password is not None: # If password field is present for update (even if empty string)
        if password.strip() and len(password.strip()) < 6: # If password is provided (not just empty string), validate length
            errors['password'] = 'Password must be at least 6 characters long.'
        # If password is an empty string or None for update, it means no change, so no error.

    # Joining Date validation (optional, but if present and not empty, must be valid format)
    joining_date_str = data.get('joining_date')
    if joining_date_str: # Only validate if present and not an empty string
        if not isinstance(joining_date_str, str): # Ensure it's a string first
            errors['joining_date'] = 'Invalid joining date format. Use YYYY-MM-DD.'
        else:
            try:
                datetime.strptime(joining_date_str, '%Y-%m-%d')
            except ValueError:
                errors['joining_date'] = 'Invalid joining date format. Use YYYY-MM-DD.'

    # Reporting Manager ID validation (optional, but if present and not empty, must be valid ObjectId)
    reporting_manager_id_str = data.get('reporting_manager_id')
    if reporting_manager_id_str: # Only validate if present and not an empty string
        if not isinstance(reporting_manager_id_str, str): # Ensure it's a string first
            errors['reporting_manager_id'] = 'Invalid reporting manager ID format.'
        else:
            try:
                ObjectId(reporting_manager_id_str)
            except:
                errors['reporting_manager_id'] = 'Invalid reporting manager ID format.'

    # Leave adjustment fields should be numbers if present
    for field in ['annual_leave_adjust', 'sick_leave_adjust', 'casual_leave_adjust']:
        value = data.get(field)
        if value is not None: # If the field is present in the data
            try:
                # Try converting to int. If it's a string like "10" it should work.
                # If it's a number already, it'll work. If it's invalid, it'll raise ValueError.
                int(value)
            except (ValueError, TypeError):
                errors[field] = f'{field.replace("_", " ").title()} must be a valid number.'

    return not bool(errors), errors # Returns (is_valid, errors_dict)


# --- End Helper Functions ---

# ########################################################################### #
# #                                DECORATORS                                 #
# ########################################################################### #
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        try:
            user = users_collection.find_one({"_id": ObjectId(session['user_id'])})
            if not user:
                session.clear()
                flash('Your session is invalid. Please log in again.', 'warning')
                return redirect(url_for('login'))
        except Exception as e:
            session.clear()
            flash('Session error. Please log in again.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard')) # Redirect to regular user dashboard
        return f(*args, **kwargs)
    return decorated_function
# --- End Decorators ---

# ########################################################################### #
# #                           WTFORMS FORM DEFINITIONS                        #
# ########################################################################### #
class AdminOwnProfileForm(FlaskForm):
    adminFirstName = StringField('First Name', validators=[DataRequired(), Length(min=1, max=100)])
    adminLastName = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=100)])
    adminEmail = StringField('Email Address', validators=[DataRequired(), Email(message="Invalid email address.")])
    submit_profile_changes = SubmitField('Save Profile Changes')
class AdminOwnChangePasswordForm(FlaskForm):
    currentPassword = PasswordField('Current Password', validators=[DataRequired()])
    newPassword = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirmNewPassword = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('newPassword')])
    submit_password_change = SubmitField('Change Password')
class UserProfileForm(FlaskForm):
    firstName = StringField('First Name', validators=[DataRequired(), Length(min=1, max=100)])
    lastName = StringField('Last Name', validators=[DataRequired(), Length(min=1, max=100)])
    submit_profile = SubmitField('Update Profile')
class UserChangePasswordForm(FlaskForm):
    currentPassword = PasswordField('Current Password', validators=[DataRequired()])
    newPassword = PasswordField('New Password', validators=[DataRequired(), Length(min=6)])
    confirmNewPassword = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('newPassword')])
    submit_password_change = SubmitField('Change Password')
LEAVE_TYPES = [('Annual', 'Annual'), ('Sick', 'Sick'), ('Casual', 'Casual'), ('Unpaid', 'Unpaid'), ('Maternity', 'Maternity'), ('Paternity', 'Paternity')]
class EditLeaveForm(FlaskForm):
    leaveType = SelectField('Leave Type', choices=LEAVE_TYPES, validators=[DataRequired()])
    startDate = DateField('Start Date', format='%Y-%m-%d', validators=[DataRequired()])
    endDate = DateField('End Date', format='%Y-%m-%d', validators=[DataRequired()])
    reason = TextAreaField('Reason', validators=[DataRequired(), Length(max=500)])
    submit = SubmitField('Update Leave Application')
# --- End WTForms Form Definitions ---

# ########################################################################### #
# #                                  ROUTES                                   #
# ########################################################################### #

# --- Core Authentication & Index Routes ---
@app.route('/')
def index():
    if 'user_id' in session: return redirect(url_for('admin_dashboard' if session.get('user_role') == 'admin' else 'dashboard'))
    return render_template('login.html', title="Login")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: return redirect(url_for('index'))

    # Initialize form_data_for_template as an empty dictionary for GET requests.
    # This ensures form_data is always defined when passed to the template.
    form_data_for_template = {}

    if request.method == 'POST':
        # When POST request, populate form_data from request.form.
        form_data_for_template = request.form

        first_name = request.form.get('firstName')
        last_name = request.form.get('lastName')
        email = request.form.get('email', '').strip().lower()
        password_from_form = request.form.get('password')
        confirm_password = request.form.get('confirmPassword')
        employee_id_str = request.form.get('employeeId')
        department = request.form.get('department', 'N/A')

        if not all([first_name, last_name, email, password_from_form, confirm_password, employee_id_str]): # Department can be N/A
            flash('All fields (except department if not specified) are required.', 'danger')
            return render_template('register.html', title="Register", form_data=form_data_for_template)

        if password_from_form != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', title="Register", form_data=form_data_for_template)

        if users_collection.find_one({'email': email}):
            flash('Email address already registered.', 'danger')
            return render_template('register.html', title="Register", form_data=form_data_for_template)

        if users_collection.find_one({'employee_id': employee_id_str}):
            flash('Employee ID already registered.', 'danger')
            return render_template('register.html', title="Register", form_data=form_data_for_template)

        leave_policy = settings_collection.find_one({"_id": "leave_policy"})
        if not leave_policy:
            # Fallback if no policy is set (should ideally be set by admin first)
            leave_policy = { "default_annual_leaves": 24, "default_sick_leaves": 12, "default_casual_leaves": 6 }

        user_data = {
            'first_name': first_name, 'last_name': last_name, 'email': email,
            'password': hash_password(password_from_form),
            'employee_id': employee_id_str,
            'employee_code': f"EMP{str(get_next_sequence('employeeId')).zfill(3)}",
            'role': 'admin' if users_collection.count_documents({}) == 0 else 'employee',
            'department': department,
            'join_date': pytz.utc.localize(datetime.utcnow()), # Store as UTC timezone-aware
            'status': 'Active',
            'leave_balance': {
                'annual': leave_policy.get('default_annual_leaves', 24),
                'sick': leave_policy.get('default_sick_leaves', 12),
                'casual': leave_policy.get('default_casual_leaves', 6)
            },
            'notification_preferences': {
                'email_on_new_leave_request': True if users_collection.count_documents({}) == 0 else False, # First admin gets this
                'email_on_leave_applied': True,
                'email_on_leave_status_change': True
            }
        }
        try:
            users_collection.insert_one(user_data)
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
             flash(f'Registration error: {e}', 'danger')
             return render_template('register.html', title="Register", form_data=form_data_for_template)

    # For GET requests (when page first loads), form_data_for_template will be an empty dict.
    return render_template('register.html', title="Register", form_data=form_data_for_template)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('index'))
    if request.method == 'POST':
        email, password = request.form.get('email','').strip().lower(), request.form.get('password')
        user = users_collection.find_one({'email': email})
        if user and check_password(user['password'], password):
            # NEW: Check if user is inactive
            if user.get('status') == 'Inactive':
                flash('Your account is currently inactive. Please contact an administrator.', 'danger')
                return render_template('login.html', title="Login", form_data=request.form)
            session.permanent = True
            session['user_id'], session['user_name'], session['user_role'] = str(user['_id']), user['first_name'], user.get('role', 'employee')
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'danger')
            return render_template('login.html', title="Login", form_data=request.form)
    return render_template('login.html', title="Login")

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Forgot Password and Reset Password Routes ---
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session: return redirect(url_for('index'))

    form_data_for_template = {}

    if request.method == 'POST':
        form_data_for_template = request.form
        email = request.form.get('email', '').strip().lower()
        user = users_collection.find_one({'email': email})

        if user:
            # Generate a secure token
            token = secrets.token_urlsafe(32)
            # Set token expiry (e.g., 1 hour from now)
            expires_at = pytz.utc.localize(datetime.utcnow()) + timedelta(hours=1)

            # Store token in database
            reset_tokens_collection.insert_one({
                '_id': token, # Using the token itself as the _id for easy lookup
                'user_id': user['_id'],
                'expires_at': expires_at, # Store as UTC timezone-aware
                'used': False,
                'created_at': pytz.utc.localize(datetime.utcnow()) # Store as UTC timezone-aware
            })

            # Prepare and send email
            reset_link = url_for('reset_password', token=token, _external=True)
            email_body_params = {
                'user_name': user.get('first_name', 'User'),
                'reset_link': reset_link,
                'expiry_hours': 1
            }
            email_html_body = render_template('email/password_reset.html', **email_body_params)
            send_email_notification(user['email'], "LeaveFlow: Password Reset Request", email_html_body)
            app.logger.info(f"Password reset link sent to {email}")

        # Always display a generic message to prevent email enumeration
        flash('If an account with that email exists, a password reset link has been sent to your inbox.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html', title="Forgot Password", form_data=form_data_for_template)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if 'user_id' in session: return redirect(url_for('index'))

    form_data_for_template = {}

    reset_token = reset_tokens_collection.find_one({'_id': token})

    # Validate the token
    if not reset_token:
        flash('Invalid or expired password reset link. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))

    # --- FIX FOR TypeError: can't compare offset-naive and offset-aware datetimes ---
    token_expiry_time = reset_token['expires_at']
    # If the retrieved datetime is naive, assume it's UTC and localize it
    if token_expiry_time.tzinfo is None or token_expiry_time.tzinfo.utcoffset(token_expiry_time) is None:
        token_expiry_time = pytz.utc.localize(token_expiry_time)

    current_utc_time = pytz.utc.localize(datetime.utcnow())

    if reset_token.get('used') or token_expiry_time < current_utc_time:
        flash('Invalid or expired password reset link. Please try again.', 'danger')
        return redirect(url_for('forgot_password'))
    # --- END FIX ---

    user = users_collection.find_one({'_id': reset_token['user_id']})
    if not user:
        flash('User associated with this reset link not found. Please try again.', 'danger')
        reset_tokens_collection.update_one({'_id': token}, {'$set': {'used': True}}) # Mark as used even if user missing
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        form_data_for_template = request.form

        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not new_password or not confirm_password:
            flash('Please enter both new password and confirm password.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters long.', 'danger')
        else:
            # Update user's password
            users_collection.update_one(
                {'_id': user['_id']},
                {'$set': {'password': hash_password(new_password)}}
            )
            # Mark token as used to prevent reuse
            reset_tokens_collection.update_one({'_id': token}, {'$set': {'used': True}})

            flash('Your password has been reset successfully. Please log in with your new password.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', title="Reset Password", token=token, form_data=form_data_for_template)
# --- END: Forgot Password and Reset Password Routes ---


# --- User Specific Routes (Employee Role) ---
@app.route('/dashboard')
@login_required
def dashboard():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

    # Existing: Fetch upcoming leaves for the user
    # Convert dates to datetime objects for proper comparison if they are strings in DB
    # Assuming start_date is stored as YYYY-MM-DD string
    today_local = pytz.utc.localize(datetime.utcnow()).astimezone(LOCAL_TIMEZONE).date() # Get today's date in local TZ
    upcoming_leaves_query = {
        "user_id": ObjectId(session['user_id']),
        "status": "Approved",
        "start_date": {"$gte": today_local.strftime('%Y-%m-%d')}
    }
    upcoming_leaves = list(leaves_collection.find(upcoming_leaves_query).sort("start_date", 1).limit(3))

    # NEW: Fetch public holidays for the current year
    # g.current_year is available from the @app.before_request function
    current_year = g.current_year
    public_holidays = list(holidays_collection.find({'year': current_year}).sort('date', 1))

    return render_template('dashboard.html',
                           title="Dashboard",
                           user=user,
                           upcoming_leaves=upcoming_leaves,
                           public_holidays=public_holidays, # Pass public holidays data
                           current_year=current_year # Pass current year for template display
                          )

@app.route('/apply-leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if request.method == 'POST':
        leave_type, start_date_str, end_date_str, reason = request.form.get('leaveType'), request.form.get('startDate'), request.form.get('endDate'), request.form.get('reason')
        if not all([leave_type, start_date_str, end_date_str, reason]):
             flash('All fields are required.', 'danger')
             return render_template('apply_leave.html', title="Apply for Leave", user=user, form_data=request.form, leave_types=LEAVE_TYPES)
        try:
            start_date_dt = datetime.strptime(start_date_str, '%Y-%m-%d')
            end_date_dt = datetime.strptime(end_date_str, '%Y-%m-%d')

            # Use current date in local timezone for comparison
            today_local = pytz.utc.localize(datetime.utcnow()).astimezone(LOCAL_TIMEZONE).date()

            if end_date_dt < start_date_dt:
                flash('End date cannot be before start date.', 'danger')
            elif start_date_dt.date() < today_local:
                flash('Start date cannot be in the past.', 'danger')
            else:
                total_days_requested = (end_date_dt - start_date_dt).days + 1
                current_type_balance = user.get('leave_balance', {}).get(leave_type.lower(), 0)
                if leave_type not in ["Unpaid", "Maternity", "Paternity"] and current_type_balance < total_days_requested:
                    flash(f'Insufficient {leave_type} leave balance. Available: {current_type_balance}, Requested: {total_days_requested}.', 'warning')
                else:
                    leave_application_data = {
                        'user_id': user['_id'],
                        'user_name': f"{user['first_name']} {user['last_name']}",
                        'employee_id': user['employee_id'],
                        'leave_type': leave_type,
                        'start_date': start_date_str, # Store as string YYYY-MM-DD
                        'end_date': end_date_str,     # Store as string YYYY-MM-DD
                        'days_count': total_days_requested,
                        'reason': reason,
                        'status': 'Pending',
                        'applied_date': pytz.utc.localize(datetime.utcnow()), # Store as UTC timezone-aware
                        'manager_comments': ''
                    }
                    inserted_leave = leaves_collection.insert_one(leave_application_data)
                    leave_id = inserted_leave.inserted_id

                    # Create in-app notification for admins, linking to the specific leave
                    create_notification(
                        recipient_id=None,
                        recipient_type="admin",
                        message=f"New {leave_type} leave request from {user['first_name']} ({user['employee_id']}).",
                        link=url_for('admin_view_leave_detail', leave_id=str(leave_id)), # Link to the new specific leave view
                        related_id=leave_id,
                        related_type="leave_application"
                    )

                    # Send email notification to admins if their preferences allow
                    admins_for_email = users_collection.find({
                        'role': 'admin',
                        'notification_preferences.email_on_new_leave_request': True
                    })
                    for admin_user in admins_for_email:
                        admin_email_subject = "LeaveFlow: New Leave Request Awaiting Your Review"
                        admin_email_body_params = {
                            'admin_name': admin_user.get('first_name', 'Admin'),
                            'applicant_name': user['first_name'],
                            'leave_type': leave_type,
                            'start_date': start_date_str,
                            'end_date': end_date_str,
                            'reason': reason,
                            'view_leave_link': url_for('admin_view_leave_detail', leave_id=str(leave_id), _external=True)
                        }
                        admin_email_html_body = render_template('email/admin_new_leave_request.html', **admin_email_body_params)
                        send_email_notification(admin_user['email'], admin_email_subject, admin_email_html_body)


                    flash('Leave application submitted successfully!', 'success')
                    return redirect(url_for('my_leaves'))
        except ValueError: flash('Invalid date format.', 'danger')
        return render_template('apply_leave.html', title="Apply for Leave", user=user, form_data=request.form, leave_types=LEAVE_TYPES)
    return render_template('apply_leave.html', title="Apply for Leave", user=user, leave_types=LEAVE_TYPES)

@app.route('/my-leaves')
@login_required
def my_leaves():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})

    # Get search query from query params
    search_query = request.args.get('search_query', '').strip()

    # Pagination parameters
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10 # Number of items per page

    # Base query for the user
    query = {
        'user_id': ObjectId(session['user_id'])
    }

    # Add search filter if search_query is provided
    if search_query:
        # Use $regex for partial, case-insensitive matching
        regex_query = {"$regex": search_query, "$options": "i"}
        # Search across 'reason', 'leave_type', and 'manager_comments'
        query['$or'] = [
            {'leave_type': regex_query},
            {'reason': regex_query},
            {'manager_comments': regex_query}
        ]

    # Get total count for pagination
    total_leaves = leaves_collection.count_documents(query)

    # Fetch paginated leaves
    user_leaves = list(leaves_collection.find(query)
                                        .sort('applied_date', -1)
                                        .skip((page - 1) * per_page)
                                        .limit(per_page))

    # Create Pagination object
    pagination = Pagination(
        page=page,
        per_page=per_page,
        total=total_leaves,
        css_framework='bootstrap4',
        display_msg="Displaying {start} - {end} of {total} leaves",
        endpoint='my_leaves',
        url_params={'search_query': search_query}
    )

    return render_template(
        'my_leaves.html',
        title="My Leaves",
        leaves=user_leaves,
        user=user,
        search_query=search_query, # Pass search_query back to template to populate input field
        pagination=pagination, # Pass pagination object to template
        current_year=g.current_year
    )

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = ObjectId(session['user_id'])
    user_from_db = users_collection.find_one({'_id': user_id})
    if not user_from_db:
        flash("User data not found.", "danger")
        return redirect(url_for('dashboard' if session.get('user_role') != 'admin' else 'admin_dashboard'))
    profile_form, password_form = UserProfileForm(), UserChangePasswordForm()
    if request.method == 'POST':
        if 'submit_profile' in request.form and profile_form.validate_on_submit():
            update_data = {}
            if profile_form.firstName.data != user_from_db.get('first_name'): update_data['first_name'] = profile_form.firstName.data
            if profile_form.lastName.data != user_from_db.get('last_name'): update_data['last_name'] = profile_form.lastName.data
            if update_data:
                users_collection.update_one({'_id': user_id}, {'$set': update_data})
                if 'first_name' in update_data: session['user_name'] = update_data['first_name']
                flash('Your profile has been updated!', 'success')
            return redirect(url_for('profile'))
        elif 'submit_password_change' in request.form and password_form.validate_on_submit():
            if not check_password(user_from_db['password'], password_form.currentPassword.data):
                flash('Incorrect current password.', 'danger')
            else:
                users_collection.update_one({'_id': user_id}, {'$set': {'password': hash_password(password_form.newPassword.data)}})
                flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('profile'))
    profile_form.firstName.data = user_from_db.get('first_name')
    profile_form.lastName.data = user_from_db.get('last_name')
    return render_template('profile.html', title="My Profile", user=user_from_db, profile_form=profile_form, password_form=password_form)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    current_prefs = user.get('notification_preferences', {})
    if request.method == 'POST':
        user_prefs_update = current_prefs.copy()
        user_prefs_update['email_on_leave_status_change'] = request.form.get('email_on_leave_status_change') == 'on'
        user_prefs_update['email_on_leave_applied'] = request.form.get('email_on_leave_applied') == 'on'
        users_collection.update_one({'_id': user['_id']}, {'$set': {'notification_preferences': user_prefs_update}})
        flash('Your notification settings have been updated!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', title="Settings", user=user, current_prefs=current_prefs)

@app.route('/leave/<leave_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_leave_application(leave_id):
    try: leave_object_id = ObjectId(leave_id)
    except Exception:
        flash('Invalid leave ID format.', 'danger')
        return redirect(url_for('my_leaves'))
    leave = leaves_collection.find_one({'_id': leave_object_id, 'user_id': ObjectId(session['user_id'])})
    if not leave:
        flash('Leave application not found or you do not have permission to edit it.', 'danger')
        return redirect(url_for('my_leaves'))
    if leave['status'] != 'Pending':
        flash('Only pending leave applications can be edited.', 'warning')
        return redirect(url_for('my_leaves'))
    form = EditLeaveForm(formdata=request.form if request.method == 'POST' else None)
    if request.method == 'GET':
        form.leaveType.data = leave.get('leave_type')
        if leave.get('start_date'):
            try: form.startDate.data = datetime.strptime(leave.get('start_date'), '%Y-%m-%d').date()
            except ValueError: app.logger.error(f"Could not parse start_date: {leave.get('start_date')}")
        if leave.get('end_date'):
            try: form.endDate.data = datetime.strptime(leave.get('end_date'), '%Y-%m-%d').date()
            except ValueError: app.logger.error(f"Could not parse end_date: {leave.get('end_date')}")
        form.reason.data = leave.get('reason')
    if form.validate_on_submit():
        user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
        new_start_date_dt, new_end_date_dt, new_leave_type, new_reason = form.startDate.data, form.endDate.data, form.leaveType.data, form.reason.data
        original_start_date_dt = datetime.strptime(leave.get('start_date'), '%Y-%m-%d').date()

        today_local = pytz.utc.localize(datetime.utcnow()).astimezone(LOCAL_TIMEZONE).date()

        if new_end_date_dt < new_start_date_dt: flash('End date cannot be before start date.', 'danger')
        elif new_start_date_dt < today_local and new_start_date_dt != original_start_date_dt: flash('Start date cannot be set to a past date if changed.', 'danger')
        else:
            new_days_count = (new_end_date_dt - new_start_date_dt).days + 1
            user_leave_balance = user.get('leave_balance', {})
            current_type_balance = user_leave_balance.get(new_leave_type.lower(), 0)
            if new_leave_type not in ["Unpaid", "Maternity", "Paternity"]:
                if current_type_balance < new_days_count:
                    flash(f'Insufficient {new_leave_type} balance. Available: {current_type_balance}, Requested: {new_days_count}.', 'warning')
                    return render_template('edit_leave_application.html', title="Edit Leave Application", form=form, leave_id=leave_id, current_leave=leave)

            # Store last_edited_date as UTC timezone-aware
            local_edited_date = pytz.utc.localize(datetime.utcnow())
            update_data = {
                'leave_type': new_leave_type,
                'start_date': new_start_date_dt.strftime('%Y-%m-%d'),
                'end_date': new_end_date_dt.strftime('%Y-%m-%d'),
                'reason': new_reason,
                'days_count': new_days_count,
                'status': 'Pending',
                'applied_date': leave.get('applied_date'), # Preserve original applied date
                'last_edited_date': local_edited_date
            }
            leaves_collection.update_one({'_id': leave_object_id}, {'$set': update_data})
            user_name_for_notif = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
            admin_message = f"Leave application (ID: {str(leave_object_id)[:6]}...) by {user_name_for_notif} has been EDITED."

            # Update notification for admin to point to the specific leave
            create_notification(
                recipient_id=None,
                recipient_type="admin",
                message=admin_message,
                link=url_for('admin_view_leave_detail', leave_id=str(leave_object_id)),
                related_id=leave_object_id,
                related_type="leave_application"
            )
            flash('Leave application updated successfully and is re-submitted for approval.', 'success')
            return redirect(url_for('my_leaves'))
    return render_template('edit_leave_application.html', title="Edit Leave Application", form=form, leave_id=leave_id, current_leave=leave)

@app.route('/leave/<leave_id>/cancel', methods=['POST'])
@login_required
def cancel_leave_application(leave_id):
    try: leave_object_id = ObjectId(leave_id)
    except Exception:
        flash('Invalid leave ID format.', 'danger')
        return redirect(url_for('my_leaves'))
    leave = leaves_collection.find_one({'_id': leave_object_id, 'user_id': ObjectId(session['user_id'])})
    if not leave:
        flash('Leave application not found or you do not have permission to cancel it.', 'danger')
        return redirect(url_for('my_leaves'))
    current_status = leave.get('status')
    user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    user_name_for_notif = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
    if current_status == 'Pending':
        leaves_collection.update_one({'_id': leave_object_id}, {'$set': {'status': 'Cancelled by User'}})
        flash('Leave application has been cancelled.', 'success')
        admin_message = f"Pending leave for {user_name_for_notif} was cancelled by the user."
        create_notification(
            recipient_id=None,
            recipient_type="admin",
            message=admin_message,
            link=url_for('admin_view_leave_detail', leave_id=str(leave_object_id)),
            related_id=leave_object_id,
            related_type="leave_application"
        )
    elif current_status == 'Approved':
        # Restore leave balance only if it's a paid leave type
        leave_type_key, days_to_restore = leave['leave_type'].lower(), leave.get('days_count', 0)
        if leave['leave_type'] not in ["Unpaid", "Maternity", "Paternity"] and days_to_restore > 0:
            users_collection.update_one({'_id': user['_id']}, {'$inc': {f'leave_balance.{leave_type_key}': days_to_restore}})
            app.logger.info(f"Restored {days_to_restore} days of {leave_type_key} for user {user['_id']} due to cancellation.")

        leaves_collection.update_one({'_id': leave_object_id}, {'$set': {'status': 'Cancelled (Approved Leave)'}})
        flash('Approved leave application has been cancelled. Your leave balance has been updated (if applicable).', 'success')
        admin_message = f"An approved leave for {user_name_for_notif} was cancelled by the user."
        create_notification(
            recipient_id=None,
            recipient_type="admin",
            message=admin_message,
            link=url_for('admin_view_leave_detail', leave_id=str(leave_object_id)),
            related_id=leave_object_id,
            related_type="leave_application"
        )
    else: flash(f"This leave application is already {current_status} and cannot be cancelled.", 'warning')
    return redirect(url_for('my_leaves'))
# --- End Edit and Cancel Leave Routes ---


# --- Admin Routes ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Fetch pending leaves for the pending table
    pending_leaves_from_db = list(leaves_collection.find({'status': 'Pending'}).sort('applied_date', 1))
    pending_leaves = serialize_mongo_data(pending_leaves_from_db)

    # Pagination parameters for All Leave History
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10 # Number of items per page

    # Search filter for All Leave History
    search_term = request.args.get('search_term', '').strip()
    history_query = {}
    if search_term:
        regex_query = {"$regex": search_term, "$options": "i"}
        history_query['$or'] = [
            {'user_name': regex_query},
            {'employee_id': regex_query},
            {'leave_type': regex_query},
            {'status': regex_query}
        ]

    total_leaves_history = leaves_collection.count_documents(history_query)
    all_leaves_from_db = list(leaves_collection.find(history_query)
                                        .sort('applied_date', -1)
                                        .skip((page - 1) * per_page)
                                        .limit(per_page))
    all_leaves = serialize_mongo_data(all_leaves_from_db)

    history_pagination = Pagination(
        page=page,
        per_page=per_page,
        total=total_leaves_history,
        css_framework='bootstrap4',
        display_msg="Displaying {start} - {end} of {total} records",
        endpoint='admin_dashboard',
        url_params={'search_term': search_term} # Preserve search term across pagination
    )

    return render_template(
        'admin_dashboard.html',
        title="Admin Dashboard",
        pending_leaves=pending_leaves,
        all_leaves=all_leaves,
        history_pagination=history_pagination,
        search_term=search_term # Pass back to template for input field
    )

@app.route('/admin/leave/<string:leave_id>')
@admin_required
def admin_view_leave_detail(leave_id):
    """Admin can view details of a specific leave application."""
    try:
        leave_object_id = ObjectId(leave_id)
    except Exception:
        flash('Invalid leave ID format.', 'danger')
        return redirect(url_for('admin_dashboard'))

    leave = leaves_collection.find_one({'_id': leave_object_id})
    if not leave:
        flash('Leave application not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Mark relevant admin notifications as read when this page is visited
    try:
        notifications_collection.update_many(
            {
                "recipient_type": "admin",
                "is_read": False,
                "related_id": leave_object_id,
                "related_type": "leave_application"
            },
            {"$set": {"is_read": True}}
        )
        app.logger.info(f"Admin notifications for leave {leave_id} marked as read by admin {session.get('user_id')}.")
    except Exception as e:
        app.logger.error(f"Error marking admin notifications for leave {leave_id} as read: {e}", exc_info=True)

    applicant_user = users_collection.find_one({'_id': leave['user_id']})

    return render_template('admin_view_leave_detail.html',
                           title="Leave Details",
                           leave=leave,
                           applicant=applicant_user)

# --- Manage Employees Page Route ---
@app.route('/admin/employees')
@admin_required
def manage_employees_page():
    return render_template('manage_employees.html') # Ensure this template name matches
# --- END Manage Employees Page Route ---

@app.route('/admin/leave/<leave_id>/<action>', methods=['POST'])
@admin_required
def manage_leave(leave_id, action):
    try: leave_object_id = ObjectId(leave_id)
    except Exception:
        flash('Invalid leave ID format.', 'danger')
        return redirect(url_for('admin_dashboard'))
    leave = leaves_collection.find_one({'_id': leave_object_id})
    if not leave:
        flash('Leave application not found.', 'danger')
        return redirect(url_for('admin_dashboard'))
    if leave.get('status') != 'Pending':
         flash(f"This leave request has already been {leave.get('status','processed').lower()}.", 'warning')
         return redirect(url_for('admin_dashboard'))

    user_id_of_applicant = leave['user_id']
    applicant_user = users_collection.find_one({'_id': user_id_of_applicant})
    if not applicant_user:
        leaves_collection.update_one({'_id': leave_object_id}, {'$set': {'status': 'Error - Applicant User Missing'}})
        flash('Applicant user for this leave not found. Status updated to reflect error.', 'danger')
        return redirect(url_for('admin_dashboard'))

    new_status, manager_comments = "", ""
    if action == 'approve':
        leave_type_key, days_taken = leave['leave_type'].lower(), leave.get('days_count', 1)
        current_balance_for_type = applicant_user.get('leave_balance', {}).get(leave_type_key, 0)
        if leave['leave_type'] not in ["Unpaid", "Maternity", "Paternity"]:
            if current_balance_for_type < days_taken:
                flash(f"Cannot approve. Insufficient {leave['leave_type']} balance for {applicant_user['first_name']}.", 'warning')
                return redirect(url_for('admin_dashboard'))
            users_collection.update_one({'_id': user_id_of_applicant}, {'$inc': {f'leave_balance.{leave_type_key}': -days_taken}})
        new_status = 'Approved'
        manager_comments = request.form.get('manager_comments', 'Approved by Admin').strip()
        update_query = {'$set': {'status': new_status, 'manager_comments': manager_comments}}
    elif action == 'reject':
        manager_comments = request.form.get('manager_comments', '').strip()
        if not manager_comments:
            flash('Please provide a reason for rejection.', 'warning')
            return redirect(url_for('admin_dashboard'))
        new_status = 'Rejected'
        update_query = {'$set': {'status': new_status, 'manager_comments': manager_comments}}
    else:
        flash('Invalid action specified.', 'danger')
        return redirect(url_for('admin_dashboard'))

    if new_status:
        update_result = leaves_collection.update_one({'_id': leave_object_id}, update_query)
        if update_result.modified_count > 0:
            flash(f"Leave for {applicant_user['first_name']} has been {new_status.lower()}.", 'success' if new_status == 'Approved' else 'info')

            # Create in-app notification for the user whose leave was updated
            in_app_message_user = f"Your {leave['leave_type']} leave ({leave['start_date']} to {leave['end_date']}) has been {new_status.lower()}."
            if new_status.lower() == 'rejected' and manager_comments: in_app_message_user += f" Reason: {manager_comments}"
            create_notification(
                recipient_id=user_id_of_applicant,
                recipient_type="user",
                message=in_app_message_user,
                link=url_for('my_leaves'),
                related_id=leave_object_id, # Link to the specific leave
                related_type="leave_application"
            )

            # Mark relevant admin notifications as read (for the *current* admin who performed the action)
            try:
                notifications_collection.update_many(
                    {
                        "recipient_type": "admin",
                        "is_read": False,
                        "related_id": leave_object_id,
                        "related_type": "leave_application",
                        # Optional: if you want to only mark notifications specifically about this leave for the current admin
                        # "link": url_for('admin_view_leave_detail', leave_id=str(leave_object_id))
                    },
                    {"$set": {"is_read": True}}
                )
                app.logger.info(f"Admin notifications related to leave {leave_id} marked as read after action '{action}'.")
            except Exception as e:
                app.logger.error(f"Error marking admin notifications for leave {leave_id} as read after action: {e}", exc_info=True)


            # Send email notification to the applicant if their preferences allow
            user_prefs, applicant_email = applicant_user.get('notification_preferences', {}), applicant_user.get('email')
            if user_prefs.get('email_on_leave_status_change', True) and applicant_email:
                email_subject_user = f"Leave Request {new_status.capitalize()}"
                email_body_params = { 'user_name': applicant_user['first_name'], 'leave_type': leave['leave_type'], 'start_date': leave['start_date'], 'end_date': leave['end_date'], 'status_text': new_status.lower(), 'comments': manager_comments, 'my_leaves_link': url_for('my_leaves', _external=True) }
                email_html_body_user = render_template('email/user_leave_status_update.html', **email_body_params)
                send_email_notification(applicant_email, email_subject_user, email_html_body_user)
        else: flash(f"Failed to update leave status for {applicant_user['first_name']}.", 'danger')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/my-profile')
@admin_required
def admin_my_profile():
    admin_user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
    if not admin_user:
        flash("Admin user data not found.", "danger")
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_my_profile.html', title="My Admin Profile", admin_user=admin_user)

@app.route('/admin/account-settings', methods=['GET', 'POST'])
@admin_required
def admin_account_settings():
    admin_user_id = ObjectId(session['user_id'])
    admin_user_from_db = users_collection.find_one({'_id': admin_user_id})
    if not admin_user_from_db:
        flash("Admin user data not found.", "danger")
        return redirect(url_for('admin_dashboard'))
    profile_form, password_form = AdminOwnProfileForm(), AdminOwnChangePasswordForm()
    current_prefs = admin_user_from_db.get('notification_preferences', {})
    if request.method == 'POST':
        if 'submit_profile_changes' in request.form and profile_form.validate_on_submit():
            update_data = {}
            if profile_form.adminFirstName.data != admin_user_from_db.get('first_name'): update_data['first_name'] = profile_form.adminFirstName.data
            if profile_form.adminLastName.data != admin_user_from_db.get('last_name'): update_data['last_name'] = profile_form.adminLastName.data
            new_email = profile_form.adminEmail.data.strip().lower()
            if new_email and new_email != admin_user_from_db.get('email'): # Only check if email has changed AND is not empty
                if users_collection.find_one({'email': new_email, '_id': {'$ne': admin_user_id}}): profile_form.adminEmail.errors.append('That email address is already in use.')
                else: update_data['email'] = new_email

            # Check if any actual changes are present before updating
            if not profile_form.adminEmail.errors and update_data: # If email validation passed and there's data to update
                users_collection.update_one({'_id': admin_user_id}, {'$set': update_data})
                if 'first_name' in update_data: session['user_name'] = update_data['first_name']
                flash('Your profile information has been updated!', 'success')
            elif not profile_form.adminEmail.errors and not update_data:
                flash('No changes detected in profile information.', 'info')

            if not profile_form.errors: # Only redirect if no errors occurred
                return redirect(url_for('admin_account_settings'))
        elif 'submit_password_change' in request.form and password_form.validate_on_submit():
            if not check_password(admin_user_from_db['password'], password_form.currentPassword.data):
                password_form.currentPassword.errors.append('Incorrect current password.')
            else:
                users_collection.update_one({'_id': admin_user_id}, {'$set': {'password': hash_password(password_form.newPassword.data)}})
                flash('Your password has been changed successfully!', 'success')
                return redirect(url_for('admin_account_settings'))
        elif 'submit_notification_prefs' in request.form:
            admin_prefs_update = current_prefs.copy()
            admin_prefs_update['email_on_new_leave_request'] = request.form.get('email_on_new_leave_request') == 'on'
            users_collection.update_one({'_id': admin_user_id}, {'$set': {'notification_preferences': admin_prefs_update}})
            flash('Admin notification preferences updated!', 'success')
            return redirect(url_for('admin_account_settings'))

    # Populate forms for GET request or if there were validation errors on POST
    profile_form.adminFirstName.data = admin_user_from_db.get('first_name')
    profile_form.adminLastName.data = admin_user_from_db.get('last_name')
    profile_form.adminEmail.data = admin_user_from_db.get('email')

    return render_template('admin_account_settings.html', title="Admin Account Settings", admin_user=admin_user_from_db, profile_form=profile_form, password_form=password_form, current_prefs=current_prefs)


@app.route('/admin/manage-leave-settings', methods=['GET', 'POST'])
@admin_required
def admin_manage_leave_settings():
    if request.method == 'POST':
        if 'update_quotas' in request.form:
            try:
                annual, sick, casual = int(request.form.get('annual_leaves')), int(request.form.get('sick_leaves')), int(request.form.get('casual_leaves'))
                settings_collection.update_one(
                    {"_id": "leave_policy"},
                    {"$set": {
                        "default_annual_leaves": annual,
                        "default_sick_leaves": sick,
                        "default_casual_leaves": casual,
                        "last_updated_by": ObjectId(session['user_id']),
                        "last_updated_on": pytz.utc.localize(datetime.utcnow()) # Store as UTC timezone-aware
                    }},
                    upsert=True
                )
                flash('Leave policy updated successfully!', 'success')
            except (ValueError, TypeError):
                flash('Invalid input. Please enter whole numbers for leave days.', 'danger')
        return redirect(url_for('admin_manage_leave_settings'))

    holidays = list(holidays_collection.find({"year": g.current_year}).sort("date", 1))
    leave_policy = settings_collection.find_one({"_id": "leave_policy"})


    return render_template(
        'admin_manage_leave_settings.html',
        title="Policy & Holiday Settings",
        policy=leave_policy,
        holidays=holidays,
        current_year=g.current_year # Ensure current_year is passed for holiday filter
    )

@app.route('/admin/add-holiday', methods=['POST'])
@admin_required
def add_holiday():
    date_str, name = request.form.get('holiday_date'), request.form.get('holiday_name')
    if not date_str or not name:
        flash('Both date and name are required for a holiday.', 'danger')
    else:
        try:
            # Holiday dates are stored as timezone-naive datetime objects (common for dates without time)
            holiday_date = datetime.strptime(date_str, '%Y-%m-%d')
            holidays_collection.insert_one({ "date": holiday_date, "name": name.strip(), "year": holiday_date.year })
            flash(f'Holiday "{name}" added successfully.', 'success')
        except Exception as e:
            flash(f'Error adding holiday: {e}', 'danger')
    return redirect(url_for('admin_manage_leave_settings'))

@app.route('/admin/delete-holiday', methods=['POST'])
@admin_required
def delete_holiday():
    holiday_id_str = request.form.get('holiday_id')
    if not holiday_id_str:
        flash('Invalid request. Holiday ID missing.', 'danger')
    else:
        try:
            result = holidays_collection.delete_one({"_id": ObjectId(holiday_id_str)})
            if result.deleted_count > 0:
                flash('Holiday deleted successfully.', 'success')
            else:
                flash('Holiday not found or already deleted.', 'warning')
        except Exception as e:
            flash(f'Error deleting holiday: {e}', 'danger')
    return redirect(url_for('admin_manage_leave_settings'))

# --- Admin Reports Routes ---
@app.route('/admin/reports')
@admin_required
def admin_reports_dashboard():
    return render_template('admin_reports_dashboard.html', title="Leave Reports")

def get_date_range(period_type="monthly", year=None, month=None, quarter=None):
    # Use UTC for internal calculations to avoid DST issues, then localize for display if needed
    now_utc = datetime.utcnow()
    if year is None: year = now_utc.year
    start_date, end_date = None, None

    if period_type == "monthly":
        if month is None: month = now_utc.month
        start_date = datetime(year, month, 1)
        next_month_val, next_year_val = (month + 1, year) if month < 12 else (1, year + 1)
        end_date = datetime(next_year_val, next_month_val, 1) - timedelta(microseconds=1)
    elif period_type == "quarterly":
        if quarter is None: quarter = (now_utc.month - 1) // 3 + 1
        if quarter == 1: start_m, end_m = 1, 3
        elif quarter == 2: start_m, end_m = 4, 6
        elif quarter == 3: start_m, end_m = 7, 9
        else: start_m, end_m = 10, 12
        start_date = datetime(year, start_m, 1)
        next_month_for_end, next_year_for_end = (end_m + 1, year) if end_m < 12 else (1, year + 1)
        end_date = datetime(next_year_for_end, next_month_for_end, 1) - timedelta(microseconds=1)
    elif period_type == "yearly":
        start_date = datetime(year, 1, 1)
        end_date = datetime(year, 12, 31, 23, 59, 59, 999999)

    # Return as timezone-naive UTC datetimes (or localized if needed for very specific queries)
    # The MongoDB query below uses string comparisons, so strftime is suitable.
    return start_date, end_date

@app.route('/admin/reports/comprehensive', methods=['GET'])
@admin_required
def admin_comprehensive_report():
    period_type = request.args.get('period_type', 'monthly')
    year = request.args.get('year', g.current_year, type=int)
    month = request.args.get('month', datetime.utcnow().month, type=int)
    quarter = request.args.get('quarter', (datetime.utcnow().month - 1) // 3 + 1, type=int)

    start_date_obj, end_date_obj = get_date_range(period_type, year, month, quarter)

    if period_type == "monthly": report_period_title_suffix = f"for {datetime(year,month,1).strftime('%B %Y')}"
    elif period_type == "quarterly": report_period_title_suffix = f"for Q{quarter} {year}"
    elif period_type == "yearly": report_period_title_suffix = f"for {year}"
    else: report_period_title_suffix = "for Selected Period"

    # Convert start_date and end_date to string format for MongoDB query,
    # assuming 'start_date' and 'end_date' fields in 'leaves' collection are stored as YYYY-MM-DD strings.
    # If they are stored as ISODate objects, remove .strftime('%Y-%m-%d') and use datetime objects directly.
    date_match_filter = {}
    if start_date_obj and end_date_obj:
        date_match_filter = {
            "start_date": {"$gte": start_date_obj.strftime('%Y-%m-%d'), "$lte": end_date_obj.strftime('%Y-%m-%d')}
        }

    employee_consumption_data, leave_type_data = [], []
    try:
        pipeline_employee = [
            {"$match": {"status": "Approved", **date_match_filter}},
            {"$lookup": {"from": users_collection.name, "localField": "user_id", "foreignField": "_id", "as": "userDetails"}},
            {"$unwind": "$userDetails"},
            {"$group": {
                "_id": "$user_id",
                "employee_name_first": {"$first": "$userDetails.first_name"},
                "employee_name_last": {"$first": "$userDetails.last_name"},
                "employee_id_val": {"$first": "$userDetails.employee_id"}, # This is the user-provided ID
                "employee_code_val": {"$first": "$userDetails.employee_code"}, # New: Generated memorable code
                "total_days_consumed": {"$sum": "$days_count"},
                "leave_breakdown": {"$push": {"leave_type": "$leave_type", "days": "$days_count"}}
            }},
            {"$project": {
                "_id": 0,
                "employee_id": "$employee_id_val",
                "employee_code": "$employee_code_val", # Include employee_code
                "employee_name": {"$concat": ["$employee_name_first", " ", "$employee_name_last"]},
                "total_days_consumed": 1,
                "leave_breakdown": 1
            }},
            {"$sort": {"total_days_consumed": -1}}
        ]
        raw_emp_data = list(leaves_collection.aggregate(pipeline_employee))
        for emp in raw_emp_data:
            summary = {}
            for item in emp["leave_breakdown"]: summary[item["leave_type"]] = summary.get(item["leave_type"], 0) + item["days"]
            emp["leave_types_summary"] = summary
            employee_consumption_data.append(emp)
    except Exception as e:
        app.logger.error(f"Error (emp consumption): {e}", exc_info=True)

    try:
        pipeline_type = [
            {"$match": {"status": "Approved", **date_match_filter}},
            {"$group": {
                "_id": "$leave_type",
                "total_applications": {"$sum": 1},
                "total_days_taken": {"$sum": "$days_count"}
            }},
            {"$project": {
                "_id": 0,
                "leave_type": "$_id",
                "total_applications": 1,
                "total_days_taken": 1
            }},
            {"$sort": {"total_days_taken": -1}}
        ]
        leave_type_data = list(leaves_collection.aggregate(pipeline_type))
    except Exception as e:
        app.logger.error(f"Error (type usage): {e}", exc_info=True)

    # --- CSV Export Logic ---
    if request.args.get('export') == 'csv':
        output = StringIO()
        writer = csv.writer(output)

        # Headers
        # Get all possible leave types to ensure comprehensive columns
        # Use a predefined list of leave types from LEAVE_TYPES for consistency
        all_leave_types_for_csv = sorted(list(set([lt[0] for lt in LEAVE_TYPES] + [lt_data['leave_type'] for lt_data in leave_type_data])))

        headers = ['Employee ID', 'Employee Code', 'Employee Name', 'Total Days Consumed'] + [f'{lt} Days' for lt in all_leave_types_for_csv]
        writer.writerow(headers)

        # Data Rows
        for emp in employee_consumption_data:
            row = [
                emp.get('employee_id', 'N/A'),
                emp.get('employee_code', 'N/A'), # Include employee_code
                emp.get('employee_name', 'Unknown'),
                emp.get('total_days_consumed', 0)
            ]
            for lt in all_leave_types_for_csv:
                # Get the summary for this leave type, default to 0 if not present
                row.append(emp.get('leave_types_summary', {}).get(lt, 0))
            writer.writerow(row)

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment;filename=comprehensive_leave_report_{period_type}_{year}.csv'}
        )
    # --- End CSV Export Logic ---

    return render_template(
        'admin_comprehensive_report.html',
        title="Comprehensive Report",
        report_period_title_suffix=report_period_title_suffix,
        employee_consumption_data=employee_consumption_data,
        leave_type_data=leave_type_data,
        period_type=period_type,
        selected_year=year,
        selected_month=month,
        selected_quarter=quarter,
        current_year=g.current_year # Pass current_year for filter dropdowns
    )

# --- Notification Routes ---
@app.route('/notifications')
@login_required
def notifications_page():
    user_id_obj, user_role = ObjectId(session['user_id']), session.get('user_role', 'employee')
    query_conditions = [{"recipient_type": "user", "recipient_id": user_id_obj}]
    if user_role == 'admin': query_conditions.append({"recipient_type": "admin"})
    query = {"$or": query_conditions}
    try:
        page, per_page = request.args.get(get_page_parameter(), type=int, default=1), 10
        total = notifications_collection.count_documents(query)
        notifications_cursor = notifications_collection.find(query).sort("created_at", -1).skip((page - 1) * per_page).limit(per_page)
        user_notifications = list(notifications_cursor)
        pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap4')
    except Exception as e:
        app.logger.error(f"Error fetching notifications: {e}", exc_info=True)
        flash("Could not load notifications.", "danger")
        pagination, user_notifications = None, []
    return render_template('notifications.html', title="Notifications", pagination=pagination, notifications=user_notifications)

@app.route('/notifications/count', methods=['GET'])
@login_required
def unread_notifications_count():
    try: user_id_obj = ObjectId(session['user_id'])
    except Exception: return jsonify({"unread_count": 0, "error": "Invalid session"}), 400
    user_role = session.get('user_role', 'employee')
    query_conditions_unread, role_specific_conditions = [{"is_read": False}], []
    if user_role == 'admin': role_specific_conditions.append({"recipient_type": "admin"})
    role_specific_conditions.append({"recipient_type": "user", "recipient_id": user_id_obj})
    query_conditions_unread.append({"$or": role_specific_conditions})
    try:
        count = notifications_collection.count_documents({"$and": query_conditions_unread})
        return jsonify({"unread_count": count})
    except Exception as e:
        app.logger.error(f"Error in /notifications/count: {e}", exc_info=True)
        return jsonify({"unread_count": 0, "error": "Failed to retrieve count"}), 500

@app.route('/notifications/mark_read/<notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try: notif_id_obj, user_id_obj = ObjectId(notification_id), ObjectId(session['user_id'])
    except Exception: return jsonify({"success": False, "message": "Invalid ID format"}), 400
    user_role, notification = session.get('user_role'), notifications_collection.find_one({"_id": notif_id_obj})
    if not notification: return jsonify({"success": False, "message": "Notification not found"}), 404
    can_mark = (notification['recipient_type'] == 'admin' and user_role == 'admin') or (notification['recipient_type'] == 'user' and notification.get('recipient_id') == user_id_obj)
    if not can_mark: return jsonify({"success": False, "message": "Unauthorized"}), 403
    try:
        result = notifications_collection.update_one({"_id": notif_id_obj}, {"$set": {"is_read": True}})
        return jsonify({"success": result.modified_count > 0})
    except Exception as e:
        app.logger.error(f"Error marking notification read: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Server error."}), 500

@app.route('/notifications/mark_all_read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try: user_id_obj = ObjectId(session['user_id'])
    except Exception: return jsonify({"success": False, "message": "Invalid session ID"}), 400
    user_role = session.get('user_role')
    query_conditions_unread, role_specific_conditions = [{"is_read": False}], []
    if user_role == 'admin': role_specific_conditions.append({"recipient_type": "admin"})
    role_specific_conditions.append({"recipient_type": "user", "recipient_id": user_id_obj})
    query_conditions_unread.append({"$or": role_specific_conditions})
    try:
        result = notifications_collection.update_many({"$and": query_conditions_unread}, {"$set": {"is_read": True}})
        return jsonify({"success": True, "modified_count": result.modified_count})
    except Exception as e:
        app.logger.error(f"Error marking all notifications read: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Server error."}), 500

@app.route('/notifications/delete/<notification_id>', methods=['POST'])
@login_required
def delete_notification(notification_id):
    try: notif_id_obj, user_id_obj = ObjectId(notification_id), ObjectId(session['user_id'])
    except Exception: return jsonify({"success": False, "message": "Invalid ID format"}), 400
    user_role, notification = session.get('user_role'), notifications_collection.find_one({"_id": notif_id_obj})
    if not notification: return jsonify({"success": False, "message": "Notification not found"}), 404
    can_delete = (notification['recipient_type'] == 'admin' and user_role == 'admin') or (notification['recipient_type'] == 'user' and notification.get('recipient_id') == user_id_obj)
    if not can_delete: return jsonify({"success": False, "message": "Unauthorized action"}), 403
    try:
        result = notifications_collection.delete_one({"_id": notif_id_obj})
        if result.deleted_count > 0: return jsonify({"success": True})
        else: return jsonify({"success": False, "message": "Could not delete notification."}), 500
    except Exception as e:
        app.logger.error(f"Error deleting notification: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Server error."}), 500
# --- End Notification Routes ---


# --- START: API Endpoints for Manage Employees ---
@app.route('/api/employees', methods=['GET'])
@admin_required
def get_employees_api():
    """Returns a list of all employees (users) with relevant details."""
    try:
        all_users = list(users_collection.find({})) # find all users

        employees_data = []
        for user in all_users:
            employee_info = {
                "id": str(user['_id']), # MongoDB _id as string for frontend use
                "employee_id": user.get('employee_id', 'N/A'), # User-provided ID
                "employee_code": user.get('employee_code', None), # Our generated memorable ID
                "name": f"{user.get('first_name', '')} {user.get('last_name', '')}".strip(),
                "email": user.get('email', 'N/A'),
                "phone": user.get('phone', ''),
                "address": user.get('address', ''),
                "designation": user.get('designation', ''),
                "department": user.get('department', 'N/A'),
                # Ensure join_date is properly formatted if it's a datetime object
                "joining_date": user.get('join_date', pytz.utc.localize(datetime.utcnow())).strftime('%Y-%m-%d') if user.get('join_date') else '', # Use UTC now if missing
                "reporting_manager_id": str(user['reporting_manager_id']) if user.get('reporting_manager_id') else None,
                "status": user.get('status', 'Active'), # Default to Active if not set
                "role": user.get('role', 'Employee'),
                "leave_balances": user.get('leave_balance', {'annual': 0, 'sick': 0, 'casual': 0})
            }
            # Ensure all leave balance types are present, default to 0
            employee_info['leave_balances']['annual'] = employee_info['leave_balances'].get('annual', 0)
            employee_info['leave_balances']['sick'] = employee_info['leave_balances'].get('sick', 0)
            employee_info['leave_balances']['casual'] = employee_info['leave_balances'].get('casual', 0)

            employees_data.append(employee_info)

        return jsonify(employees_data)
    except Exception as e:
        app.logger.error(f"Error fetching employees: {e}", exc_info=True)
        return jsonify({"message": "Failed to fetch employees"}), 500

@app.route('/api/employees/<string:employee_id_str>', methods=['GET'])
@admin_required
def get_employee_api(employee_id_str):
    """Returns details of a specific employee by their _id."""
    try:
        employee = users_collection.find_one({"_id": ObjectId(employee_id_str)})
        if employee:
            employee_info = {
                "id": str(employee['_id']),
                "employee_id": employee.get('employee_id', 'N/A'),
                "employee_code": employee.get('employee_code', None), # Our generated memorable ID
                "name": f"{employee.get('first_name', '')} {employee.get('last_name', '')}".strip(),
                "email": employee.get('email', 'N/A'),
                "phone": employee.get('phone', ''),
                "address": employee.get('address', ''),
                "designation": employee.get('designation', ''),
                "department": employee.get('department', 'N/A'),
                "joining_date": employee.get('join_date', pytz.utc.localize(datetime.utcnow())).strftime('%Y-%m-%d') if employee.get('join_date') else '', # Use UTC now if missing
                "reporting_manager_id": str(employee['reporting_manager_id']) if employee.get('reporting_manager_id') else None,
                "status": employee.get('status', 'Active'), # Default to Active
                "role": employee.get('role', 'Employee'),
                "leave_balances": employee.get('leave_balance', {'annual': 0, 'sick': 0, 'casual': 0})
            }
            # Ensure all leave balance types are present, default to 0
            employee_info['leave_balances']['annual'] = employee_info['leave_balances'].get('annual', 0)
            employee_info['leave_balances']['sick'] = employee_info['leave_balances'].get('sick', 0)
            employee_info['leave_balances']['casual'] = employee_info['leave_balances'].get('casual', 0)

            return jsonify(employee_info)
        return jsonify({"message": "Employee not found"}), 404
    except Exception as e:
        app.logger.error(f"Error fetching employee {employee_id_str}: {e}", exc_info=True)
        return jsonify({"message": "Failed to fetch employee details"}), 500

@app.route('/api/employees', methods=['POST'])
@admin_required
def add_employee_api():
    """Adds a new employee (user) to the database."""
    data = request.json

    # Validate incoming data using the helper function
    is_valid, errors = validate_employee_data(data, is_new_employee=True)
    if not is_valid:
        app.logger.warning(f"Failed to add employee due to validation errors: {errors}") # Log validation errors
        return jsonify({"message": "Validation failed.", "errors": errors}), 400

    # Generate Memorable Employee Code
    next_seq = get_next_sequence('employeeId')
    memorable_employee_code = f"EMP{str(next_seq).zfill(3)}" # E.g., EMP001

    # Get default leave policy from settings or use hardcoded defaults
    leave_policy = settings_collection.find_one({"_id": "leave_policy"})
    default_annual = leave_policy.get('default_annual_leaves', 24) if leave_policy else 24
    default_sick = leave_policy.get('default_sick_leaves', 12) if leave_policy else 12
    default_casual = leave_policy.get('default_casual_leaves', 6) if leave_policy else 6

    # Apply initial adjustments if provided, otherwise use defaults
    initial_annual = default_annual + int(data.get('annual_leave_adjust', 0))
    initial_sick = default_sick + int(data.get('sick_leave_adjust', 0))
    initial_casual = default_casual + int(data.get('casual_leave_adjust', 0))

    # Split name into first and last (simple approach, might need refinement)
    full_name = data['name'].strip()
    name_parts = full_name.split(' ', 1)
    first_name = name_parts[0]
    last_name = name_parts[1] if len(name_parts) > 1 else ''

    new_employee_doc = {
        "first_name": first_name,
        "last_name": last_name,
        "email": data['email'].lower().strip(),
        "password": hash_password(data['password']), # Hash the password
        "employee_id": data['employee_id'], # User-provided
        "employee_code": memorable_employee_code, # System-generated
        "phone": data.get('phone', ''),
        "address": data.get('address', ''),
        "designation": data.get('designation', ''),
        "department": data.get('department', 'N/A'),
        "join_date": pytz.utc.localize(datetime.strptime(data['joining_date'], '%Y-%m-%d')) if data.get('joining_date') else None, # Store as UTC aware datetime, or None if empty
        "reporting_manager_id": ObjectId(data['reporting_manager_id']) if data.get('reporting_manager_id') else None,
        "status": data.get('status', 'Active'), # Default to Active
        "role": data.get('role', 'Employee'),
        "leave_balance": {
            "annual": initial_annual,
            "sick": initial_sick,
            "casual": initial_casual
        },
        "notification_preferences": { # Default preferences for new users
            'email_on_new_leave_request': False,
            'email_on_leave_applied': True,
            'email_on_leave_status_change': True
        }
    }

    try:
        insert_result = users_collection.insert_one(new_employee_doc)

        # Prepare response (remove sensitive data)
        response_employee = {
            "id": str(insert_result.inserted_id),
            "employee_id": new_employee_doc['employee_id'],
            "employee_code": new_employee_doc['employee_code'],
            "name": new_employee_doc['first_name'] + ' ' + new_employee_doc['last_name'],
            "email": new_employee_doc['email'],
            "department": new_employee_doc['department'],
            "status": new_employee_doc['status'],
            "role": new_employee_doc['role'],
            "leave_balances": new_employee_doc['leave_balance']
        }
        return jsonify({"message": "Employee added successfully", "employee": response_employee}), 201
    except Exception as e:
        app.logger.error(f"Error adding employee: {e}", exc_info=True)
        return jsonify({"message": "Failed to add employee"}), 500

@app.route('/api/employees/<string:employee_id_str>', methods=['PUT'])
@admin_required
def update_employee_api(employee_id_str):
    """Updates an existing employee's details."""
    data = request.json

    try:
        employee_obj_id = ObjectId(employee_id_str)
        employee = users_collection.find_one({"_id": employee_obj_id})

        if not employee:
            return jsonify({"message": "Employee not found"}), 404

        # Validate incoming data using the helper function
        # Pass current_employee_id to allow uniqueness checks to ignore self
        is_valid, errors = validate_employee_data(data, is_new_employee=False, current_employee_id=employee_obj_id)
        if not is_valid:
            app.logger.warning(f"Failed to update employee {employee_id_str} due to validation errors: {errors}") # Log validation errors
            return jsonify({"message": "Validation failed.", "errors": errors}), 400

        update_fields = {}
        # Update basic profile fields
        full_name = data.get('name', '').strip()
        if 'name' in data: # Only update if name is explicitly provided in the request body
            name_parts = full_name.split(' ', 1)
            update_fields['first_name'] = name_parts[0]
            update_fields['last_name'] = name_parts[1] if len(name_parts) > 1 else ''

        # Email update (already validated for uniqueness and format by helper)
        if 'email' in data: # Only update if email is explicitly provided
            new_email = data.get('email', '').lower().strip()
            if new_email: # Only set if it's not an empty string (validation ensures it's valid if not empty)
                update_fields['email'] = new_email

        # Password update (only if provided and valid length)
        if 'password' in data and data.get('password') and data.get('password').strip():
            update_fields['password'] = hash_password(data['password'])

        # Employee ID update (already validated for uniqueness by helper)
        if 'employee_id' in data:
            update_fields['employee_id'] = data['employee_id']

        if 'phone' in data: update_fields['phone'] = data['phone']
        if 'address' in data: update_fields['address'] = data['address']
        if 'designation' in data: update_fields['designation'] = data['designation']
        if 'department' in data: update_fields['department'] = data['department']

        # Joining Date (already validated for format by helper)
        if 'joining_date' in data: # Check if key is explicitly present
            if data['joining_date']: # If value is not empty string or None
                update_fields['join_date'] = pytz.utc.localize(datetime.strptime(data['joining_date'], '%Y-%m-%d'))
            else: # If value is an empty string or None (client wants to clear it)
                update_fields['join_date'] = None # Set to None in DB

        if 'status' in data: update_fields['status'] = data['status']
        if 'role' in data: update_fields['role'] = data['role']

        # Reporting Manager ID - convert to ObjectId or None (already validated by helper for format)
        if 'reporting_manager_id' in data: # Check if key is explicitly present
            if data['reporting_manager_id']: # If value is not empty string or None
                update_fields['reporting_manager_id'] = ObjectId(data['reporting_manager_id'])
            else: # If value is an empty string or None (client wants to clear it)
                update_fields['reporting_manager_id'] = None # Set to None in DB

        # Handle leave balance adjustments using $inc
        leave_balance_increments = {}
        # Ensure only valid integer adjustments are applied.
        # Check if the key exists AND is a number (int/float allowed by json, but we need int)
        for field, db_field in [('annual_leave_adjust', 'annual'), ('sick_leave_adjust', 'sick'), ('casual_leave_adjust', 'casual')]:
            if field in data and data[field] is not None:
                try:
                    # int() will handle both int and float values (truncating floats) or convert from string
                    leave_balance_increments[f'leave_balance.{db_field}'] = int(data[field])
                except (ValueError, TypeError):
                    # This case should ideally be caught by validate_employee_data already,
                    # but as a fallback, it will skip invalid adjustments.
                    app.logger.warning(f"Skipping invalid {field}: {data[field]}")


        update_operations = {}
        if update_fields:
            update_operations['$set'] = update_fields
        if leave_balance_increments:
            update_operations['$inc'] = leave_balance_increments

        if not update_operations:
            return jsonify({"message": "No changes provided to update"}), 200 # No actual update needed

        update_result = users_collection.update_one({"_id": employee_obj_id}, update_operations)

        if update_result.modified_count > 0:
            updated_employee = users_collection.find_one({"_id": employee_obj_id})
            # Prepare response (remove sensitive data)
            response_employee = {
                "id": str(updated_employee['_id']),
                "employee_id": updated_employee.get('employee_id', 'N/A'),
                "employee_code": updated_employee.get('employee_code', None),
                "name": f"{updated_employee.get('first_name', '')} {updated_employee.get('last_name', '')}".strip(),
                "email": updated_employee.get('email', 'N/A'),
                "department": updated_employee.get('department', 'N/A'),
                "status": updated_employee.get('status', 'Active'),
                "role": updated_employee.get('role', 'Employee'),
                "leave_balances": updated_employee.get('leave_balance', {'annual': 0, 'sick': 0, 'casual': 0})
            }
            # Ensure all leave balance types are present, default to 0
            response_employee['leave_balances']['annual'] = response_employee['leave_balances'].get('annual', 0)
            response_employee['leave_balances']['sick'] = response_employee['leave_balances'].get('sick', 0)
            response_employee['leave_balances']['casual'] = response_employee['leave_balances'].get('casual', 0)

            return jsonify({"message": "Employee updated successfully", "employee": response_employee}), 200
        else:
            return jsonify({"message": "No changes made or employee not found"}), 200 # Or 404 if you want to be strict
    except Exception as e:
        app.logger.error(f"Error updating employee {employee_id_str}: {e}", exc_info=True)
        return jsonify({"message": "Failed to update employee"}), 500

# NEW: Soft Delete (Inactivate) Employee
@app.route('/api/employees/<string:employee_id_str>/inactivate', methods=['PUT'])
@admin_required
def soft_delete_employee_api(employee_id_str):
    """Sets an employee's status to Inactive (soft delete)."""
    try:
        obj_id = ObjectId(employee_id_str)
        result = users_collection.update_one({'_id': obj_id}, {'$set': {'status': 'Inactive'}})
        if result.modified_count == 1:
            # Also update any pending leaves to 'Rejected (User Inactivated)' for clarity
            leaves_collection.update_many(
                {'user_id': obj_id, 'status': 'Pending'},
                {'$set': {'status': 'Rejected (User Inactivated)', 'manager_comments': 'User account inactivated'}}
            )
            return jsonify({'message': 'Employee inactivated successfully'}), 200
        return jsonify({'message': 'Employee not found or already inactive'}), 404
    except Exception as e:
        app.logger.error(f"Error inactivating employee: {e}", exc_info=True)
        return jsonify({'message': f'Error inactivating employee: {str(e)}'}), 400

# NEW: Restore (Activate) Employee
@app.route('/api/employees/<string:employee_id_str>/activate', methods=['PUT'])
@admin_required
def api_activate_employee(employee_id_str):
    """Sets an employee's status to Active."""
    try:
        obj_id = ObjectId(employee_id_str)
        result = users_collection.update_one({'_id': obj_id}, {'$set': {'status': 'Active'}})
        if result.modified_count == 1:
            return jsonify({'message': 'Employee restored successfully'}), 200
        return jsonify({'message': 'Employee not found or already active'}), 404
    except Exception as e:
        app.logger.error(f"Error restoring employee: {e}", exc_info=True)
        return jsonify({'message': f'Error restoring employee: {str(e)}'}), 400

# --- END: API Endpoints for Manage Employees ---


# --- START: Footer Informational Page Routes ---
@app.route('/company-policy')
@login_required
def company_policy_footer(): return render_template('company_policy.html', title="Company Leave Policy")
@app.route('/help-support')
@login_required
def help_support_footer(): return render_template('help_support.html', title="Help & Support")
@app.route('/about-us')
def about_us_footer(): return render_template('about_us.html', title="About LeaveFlow")
@app.route('/features')
def features_footer(): return render_template('features.html', title="LeaveFlow Features")
@app.route('/contact-us')
def contact_us_footer(): return render_template('contact_us.html', title="Contact Us")
@app.route('/privacy-policy')
def privacy_policy_footer(): return render_template('privacy_policy.html', title="Privacy Policy")
@app.route('/terms-of-service')
def terms_service_footer(): return render_template('terms_service.html', title="Terms of Service")
@app.route('/cookie-policy')
def cookie_policy_footer(): return render_template('cookie_policy.html', title="Cookie Policy")
# --- END: Footer Informational Page Routes ---


# ########################################################################### #
# #                             FLASK CLI COMMANDS                            #
# ########################################################################### #
@app.cli.command('create-admin')
@click.option('--fname', prompt="Admin First Name")
@click.option('--lname', prompt="Admin Last Name")
@click.option('--email', prompt="Admin Email")
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--empid', prompt="Admin Employee ID (e.g., A101)")
@click.option('--department', prompt="Admin Department", default="Administration")
@with_appcontext
def create_admin_command(fname, lname, email, password, empid, department):
    email = email.strip().lower()
    if users_collection.find_one({'email': email}):
        click.echo(click.style(f'Error: User with email {email} already exists.', fg='red'), err=True)
        return
    if users_collection.find_one({'employee_id': empid}): # This is the user-provided ID
        click.echo(click.style(f'Error: User with employee ID {empid} already exists.', fg='red'), err=True)
        return

    # Generate Memorable Employee Code for Admin
    next_seq = get_next_sequence('employeeId')
    memorable_employee_code = f"EMP{str(next_seq).zfill(3)}"

    hashed_pw = hash_password(password)
    admin_data = {
        'first_name': fname.strip(), 'last_name': lname.strip(), 'email': email,
        'password': hashed_pw,
        'employee_id': empid.strip(), # User-provided
        'employee_code': memorable_employee_code, # System-generated
        'role': 'admin',
        'department': department.strip(),
        'join_date': pytz.utc.localize(datetime.utcnow()), # Store as UTC timezone-aware
        'leave_balance': {'annual': 50, 'sick': 24, 'casual': 12},
        'notification_preferences': { 'email_on_new_leave_request': True, 'email_on_leave_applied': True, 'email_on_leave_status_change': True },
        'designation': 'Admin',
        'phone': '',
        'address': '',
        'reporting_manager_id': None, # Admin usually doesn't report to anyone
        'status': 'Active' # Admin is active by default
    }
    try:
        users_collection.insert_one(admin_data)
        click.echo(click.style(f'Admin user {email} (Employee Code: {memorable_employee_code}) created successfully!', fg='green'))
    except Exception as e: click.echo(click.style(f'Error creating admin user: {e}', fg='red'), err=True)
# --- End CLI Commands ---

# ########################################################################### #
# #                                 APP RUN                                   #
# ########################################################################### #
if __name__ == '__main__':
    is_debug = os.getenv('FLASK_DEBUG', '0').lower() in ['true', '1', 't']
    app.logger.info(f"Starting Flask app in {'DEBUG' if is_debug else 'PRODUCTION'} mode.")
    app.run(debug=is_debug, host='0.0.0.0', port=int(os.getenv("PORT", 5000)))