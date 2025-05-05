from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_bcrypt import Bcrypt
from flask_session import Session
import os
import json
import hashlib
import logging
import sqlite3
import time
import uuid
import re
import smtplib
import secrets
import datetime
import base64
from email.message import EmailMessage
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from dotenv import load_dotenv
from supabase import create_client, Client
# Import direct database utilities
from db_utils import find_user, insert_user, update_user, verify_password, get_user_chats, insert_chat
import os
import datetime
import logging
import urllib.parse
import json
from chat import chat_bp, set_supabase_client

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)
bcrypt = Bcrypt(app)

# Force reload environment variables to ensure we get the latest values
load_dotenv(override=True)

# Email configuration - Gmail SMTP
EMAIL_SENDER = os.getenv('EMAIL_SENDER', 'cyberai.help@gmail.com')
EMAIL_SENDER_NAME = os.getenv('EMAIL_SENDER_NAME', 'Security Analyzer')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD', '')
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '465'))
DEPLOYMENT_MODE = os.getenv('DEPLOYMENT_MODE', 'false').lower() == 'true'

# Log Gmail SMTP configuration
masked_password = '****' if GMAIL_APP_PASSWORD else '(not set)'
logger.info(f"Gmail SMTP configuration: Server: {SMTP_SERVER}:{SMTP_PORT}, Sender: {EMAIL_SENDER}")
logger.info(f"App Password: {masked_password}")
logger.info(f"Deployment mode: {DEPLOYMENT_MODE}")

# Create a serializer for token generation
ts = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Check if we should use Supabase
use_supabase = os.getenv('USE_SUPABASE', 'false').lower() == 'true'

# Check if we should use mock database
use_mock_db = os.getenv('MOCK_DB', 'true').lower() == 'true'  # Default to true for reliability
if use_mock_db:
    logger.info("MOCK_DB flag is set to true, using mock database")

# Initialize database variables
supabase = None

# Mock database for development
mock_users = []
mock_scans = []

def create_mock_database():
    global mock_users, mock_scans
    logger.info("Creating mock database for development")
    
    # Create a default admin user if not exists
    admin_exists = False
    for user in mock_users:
        if user.get('email') == 'admin@example.com':
            admin_exists = True
            break
    
    if not admin_exists:
        # Create a new password hash that will work with our bcrypt setup
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        mock_users.append({
            'email': 'admin@example.com',
            'password': admin_password,
            'name': 'Admin User',
            'created_at': datetime.datetime.now(),
            'security_score': 85,
            'passwords_protected': 3,
            'threats_blocked': 12
        })
        logger.info("Created mock database with default admin user: admin@example.com / admin123")
        logger.info(f"Admin password hash: {admin_password}")
        
    # Create a test user if not exists
    test_exists = False
    for user in mock_users:
        if user.get('email') == 'test@example.com':
            test_exists = True
            break
    
    if not test_exists:
        # Create a test user with a simple password
        test_password = bcrypt.generate_password_hash('test123').decode('utf-8')
        mock_users.append({
            'email': 'test@example.com',
            'password': test_password,
            'name': 'Test User',
            'created_at': datetime.datetime.now(),
            'security_score': 50,
            'passwords_protected': 1,
            'threats_blocked': 5
        })
        logger.info("Created mock database with test user: test@example.com / test123")
        logger.info(f"Test password hash: {test_password}")
        
    # Log all users in the mock database
    logger.info(f"Mock database contains {len(mock_users)} users:")
    for user in mock_users:
        logger.info(f"  - {user['email']} ({user['name']})")

# Mock database functions
def mock_find_user(email):
    for user in mock_users:
        if user.get('email') == email:
            return user
    return None

def mock_insert_user(user_data):
    mock_users.append(user_data)
    return True

def mock_insert_scan(scan_data):
    mock_scans.append(scan_data)
    return True

def mock_find_scans(email):
    return [scan for scan in mock_scans if scan.get('user_email') == email]

# Initialize Supabase client
def init_supabase():
    global supabase
    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_KEY')
        
        if not supabase_url or not supabase_key:
            raise ValueError("Supabase URL or key is not set")
        
        logger.info(f"Connecting to Supabase at: {supabase_url}")
        logger.info(f"Using key: {supabase_key[:10]}...")
        supabase = create_client(supabase_url, supabase_key)
        
        # Test the connection by checking if we can access the database
        logger.info("Testing Supabase connection...")
        try:
            # Try to access the users table
            response = supabase.table('users').select("*").limit(1).execute()
            logger.info(f"Supabase connection successful. Response: {response}")
            
            # Pass the Supabase client to the chat module
            from chat import set_supabase_client
            set_supabase_client(supabase)
            
            return True  # Return True to indicate successful initialization
        except Exception as e:
            logger.error(f"Supabase connection test failed: {str(e)}")
            return False
            
    except Exception as e:
        logger.error(f"Error initializing Supabase: {str(e)}")
        return False

# Supabase database functions
def supabase_find_user(email):
    try:
        response = supabase.table('users').select("*").eq('email', email).execute()
        data = response.data
        logger.info(f"Supabase find_user response for {email}: {data}")
        if data and len(data) > 0:
            # Ensure the user data has the expected fields
            user = data[0]
            # Make sure the user has a name field (some databases might use username instead)
            if 'name' not in user and 'username' in user:
                user['name'] = user['username']
            return user
        return None
    except Exception as e:
        logger.error(f"Error finding user in Supabase: {str(e)}")
        return None

def supabase_insert_user(user_data):
    try:
        # Convert datetime objects to ISO format strings for JSON serialization
        if 'created_at' in user_data and isinstance(user_data['created_at'], datetime.datetime):
            user_data['created_at'] = user_data['created_at'].isoformat()
        
        # Log the user data being inserted (excluding password)
        log_data = user_data.copy()
        if 'password' in log_data:
            log_data['password'] = '***REDACTED***'
        logger.info(f"Inserting user into Supabase: {log_data}")
        
        # Create a simplified user object with only the required fields
        # This helps avoid issues with column mismatches
        simplified_user = {
            'email': user_data['email'],
            'password': user_data['password'],
            'name': user_data['name']
        }
        
        # Add optional fields if they exist in the database
        if 'created_at' in user_data:
            simplified_user['created_at'] = user_data['created_at']
        
        # Check if the users table exists and has the required columns
        try:
            # Try to get the table structure
            table_check = supabase.table('users').select('id').limit(1).execute()
            logger.info(f"Table check response: {table_check}")
        except Exception as table_e:
            logger.error(f"Error checking users table: {str(table_e)}")
            return False
            
        response = supabase.table('users').insert(simplified_user).execute()
        logger.info(f"User insertion response: {response}")
        return True
    except Exception as e:
        logger.error(f"Error inserting user in Supabase: {str(e)}")
        return False

def supabase_update_user(email, update_data):
    try:
        response = supabase.table('users').update(update_data).eq('email', email).execute()
        return True
    except Exception as e:
        logger.error(f"Error updating user in Supabase: {str(e)}")
        return False

def supabase_insert_scan(scan_data):
    try:
        # Convert datetime objects to ISO format strings for JSON serialization
        if 'timestamp' in scan_data and isinstance(scan_data['timestamp'], datetime.datetime):
            scan_data['timestamp'] = scan_data['timestamp'].isoformat()
            
        # Convert result to JSON string if it's a dict
        if 'result' in scan_data and isinstance(scan_data['result'], dict):
            scan_data['result'] = json.dumps(scan_data['result'])
            
        response = supabase.table('scans').insert(scan_data).execute()
        return True
    except Exception as e:
        logger.error(f"Error inserting scan in Supabase: {str(e)}")
        return False

def supabase_find_scans(email):
    try:
        response = supabase.table('scans').select("*").eq('user_email', email).execute()
        scans = response.data
        
        # Parse JSON strings back to dictionaries
        for scan in scans:
            if 'result' in scan and isinstance(scan['result'], str):
                try:
                    scan['result'] = json.loads(scan['result'])
                except:
                    pass  # Keep as string if not valid JSON
                    
        return scans
    except Exception as e:
        logger.error(f"Error finding scans in Supabase: {str(e)}")
        return []

# Initialize the appropriate database
if use_mock_db:
    create_mock_database()
elif use_supabase:
    supabase_initialized = init_supabase()
    if not supabase_initialized:
        logger.error("Failed to initialize Supabase. Falling back to mock database.")
        use_mock_db = True
        use_supabase = False
        create_mock_database()
    else:
        # Pass the Supabase client to the chat module
        from chat import set_supabase_client
        set_supabase_client(supabase)

# Database abstraction functions
def find_user(email):
    # Always use direct PostgreSQL connection to bypass RLS
    from db_utils import find_user as direct_find_user
    return direct_find_user(email)

def insert_user(user_data):
    # Always use direct PostgreSQL connection to bypass RLS
    from db_utils import insert_user as direct_insert_user
    return direct_insert_user(user_data)

def update_user(email, update_data):
    # Always use direct PostgreSQL connection to bypass RLS
    from db_utils import update_user as direct_update_user
    return direct_update_user(email, update_data)

def insert_scan(scan_data):
    if use_mock_db:
        return mock_insert_scan(scan_data)
    elif use_supabase:
        return supabase_insert_scan(scan_data)
    else:
        logger.error("No database configuration is active")
        return False

def find_scans(email):
    if use_mock_db:
        return mock_find_scans(email)
    elif use_supabase:
        return supabase_find_scans(email)
    else:
        logger.error("No database configuration is active")
        return []

# Routes
@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        logger.info(f"Login attempt for email: {email}")
        
        # Find user directly using PostgreSQL connection
        user = find_user(email)
        logger.info(f"User found: {user is not None}")
        
        # Try both verification methods (direct DB first, then bcrypt)
        password_valid = False
        
        try:
            # Try direct verification first
            password_valid = verify_password(email, password)
            logger.info(f"Direct password verification result: {password_valid}")
        except Exception as e:
            logger.error(f"Error in direct password verification: {str(e)}")
        
        # If direct verification failed, try bcrypt check as fallback
        if not password_valid and user and 'password' in user and user['password']:
            try:
                password_valid = bcrypt.check_password_hash(user['password'], password)
                logger.info(f"Bcrypt password validation result: {password_valid}")
            except Exception as bc_err:
                logger.error(f"Error in bcrypt password check: {str(bc_err)}")
            
        if password_valid:
            logger.info(f"Password check passed for {email}")
            session['user'] = {
                'email': user['email'],
                'name': user.get('name', 'User')
            }
            logger.info(f"Session created for {email}: {session['user']}")
            return redirect(url_for('dashboard'))
        else:
            if user:
                logger.warning(f"Password check failed for {email}")
                if 'password' not in user or not user['password']:
                    logger.error(f"User record has no password or empty password: {user}")
            else:
                logger.warning(f"No user found with email: {email}")
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        logger.info(f"Signup attempt for email: {email}")
        
        if not name or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        # Check if user exists directly in database
        existing_user = find_user(email)
        
        if existing_user:
            logger.warning(f"Signup failed: Email already exists: {email}")
            flash('Email already exists', 'error')
            return render_template('signup.html')
        else:
            try:
                # Generate password hash
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                logger.info(f"Generated password hash for {email}: {hashed_password[:20]}...")
                
                # Create a user object with all required fields
                user_data = {
                    'name': name,
                    'email': email,
                    'password': hashed_password,
                    'created_at': datetime.datetime.now().isoformat(),
                    'is_active': True,
                    'is_verified': False,
                    'is_admin': False
                }
                
                # Insert user directly to the database, bypassing Supabase RLS
                success = insert_user(user_data)
                
                if success:
                    logger.info(f"Account created successfully for {email}")
                    flash('Account created successfully. Please log in.', 'success')
                    return redirect(url_for('login'))
                else:
                    logger.error(f"Error creating account for {email}")
                    flash('Error creating account. Please try again.', 'error')
                    return render_template('signup.html')
            except Exception as e:
                logger.error(f"Error in signup: {str(e)}")
                flash('An error occurred. Please try again.', 'error')
                return render_template('signup.html')
    
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        logger.warning("Attempted to access dashboard without being logged in")
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    logger.info(f"Dashboard access by {user_email}")
    
    # Get user data
    user_data = find_user(user_email)
    if not user_data:
        logger.error(f"User data not found for {user_email} despite valid session")
        session.pop('user', None)
        return redirect(url_for('login'))
    
    # Get user's scans
    scans = find_scans(user_email)
    logger.info(f"Found {len(scans)} scans for {user_email}")
    
    # Update session data with complete user info
    session_user = {
        'email': user_data['email'],
        'name': user_data.get('name', 'User'),
        'security_score': user_data.get('security_score', 0),
        'passwords_protected': user_data.get('passwords_protected', 0),
        'threats_blocked': user_data.get('threats_blocked', 0)
    }
    
    return render_template('dashboard.html', user=session_user, scans=scans)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

# Function to send password reset email
def send_password_reset_email(email, reset_url):
    # Log key configuration details
    logger.info(f"Email sending mode: {'Production' if DEPLOYMENT_MODE else 'Development'}")
    
    try:
        # Log email sending attempt
        logger.info(f"Attempting to send password reset email to {email}")
        logger.info(f"Reset URL: {reset_url}")
        
        # Always log the reset URL for debugging
        logger.info(f"Password reset URL for {email}: {reset_url}")
        
        # In development mode, just return success without sending email
        if not DEPLOYMENT_MODE:
            logger.info(f"Development mode: Not sending actual email")
            return True
        
        # In production mode, send an actual email
        try:
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Password Reset Request - Security Analyzer'
            msg['From'] = f"{EMAIL_SENDER_NAME} <{EMAIL_SENDER}>"
            msg['To'] = email
            msg['Reply-To'] = EMAIL_SENDER
            
            # Add anti-spam headers
            msg['Message-ID'] = f"<{secrets.token_hex(16)}@securityanalyzer.app>"
            msg['Date'] = datetime.datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z")
            msg['X-Priority'] = '3'
            
            # Create a safer HTML content with direct URL insertion for better deliverability
            reset_url_clean = reset_url.replace('&', '&amp;')  # HTML escape & characters
            
            html_content = f'''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Password Reset</title>
            </head>
            <body style="margin: 0; padding: 0; font-family: Arial, Helvetica, sans-serif; background-color: #f7f7f7;">
                <table role="presentation" width="100%" style="border-collapse: collapse;">
                    <tr>
                        <td align="center" style="padding: 20px 0;">
                            <table role="presentation" style="max-width: 600px; width: 100%; border-collapse: collapse; background-color: #ffffff; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1);">
                                <!-- Header -->
                                <tr>
                                    <td style="background-color: #4f46e5; padding: 20px; text-align: center; border-radius: 8px 8px 0 0;">
                                        <h1 style="color: white; margin: 0; font-size: 24px;">Security Analyzer</h1>
                                    </td>
                                </tr>
                                <!-- Content -->
                                <tr>
                                    <td style="padding: 30px;">
                                        <h2 style="margin-top: 0; color: #333333;">Password Reset Request</h2>
                                        <p style="color: #555555; line-height: 1.5;">We received a request to reset your password. Click the button below to create a new password:</p>
                                        <div style="text-align: center; margin: 30px 0;">
                                            <!-- Use table-based button for better email client compatibility -->
                                            <table role="presentation" cellspacing="0" cellpadding="0" border="0" align="center" style="margin: auto;">
                                                <tr>
                                                    <td style="border-radius: 4px; background: #4f46e5; text-align: center;">
                                                        <a href="{reset_url_clean}" target="_blank" style="background: #4f46e5; border: 15px solid #4f46e5; font-family: sans-serif; font-size: 14px; line-height: 1.1; text-align: center; text-decoration: none; display: block; border-radius: 4px; font-weight: bold; color: #ffffff !important;">Reset Password</a>
                                                    </td>
                                                </tr>
                                            </table>
                                        </div>
                                        
                                        <!-- Prominent text link as fallback -->
                                        <div style="text-align: center; margin: 25px 0 15px;">
                                            <p style="font-size: 13px; color: #666; margin-bottom: 10px;">If the button doesn't work, click or copy the link below:</p>
                                            <a href="{reset_url_clean}" style="color: #4f46e5; font-weight: bold; text-decoration: underline;">{reset_url_clean}</a>
                                        </div>
                                        <p style="color: #555555; line-height: 1.5;">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                                        <p style="color: #555555; line-height: 1.5;">This link will expire in 30 minutes for security reasons.</p>
                                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eeeeee;">
                                            <p style="color: #555555; margin-bottom: 5px;">Best regards,</p>
                                            <p style="color: #555555; font-weight: bold; margin-top: 0;">The Security Analyzer Team</p>
                                        </div>
                                    </td>
                                </tr>
                                <!-- Footer -->
                                <tr>
                                    <td style="background-color: #f3f4f6; padding: 15px; text-align: center; font-size: 12px; color: #6b7280; border-radius: 0 0 8px 8px;">
                                        <p style="margin: 0;">&copy; 2025 Security Analyzer. All rights reserved.</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
            '''
            
            # Add plain text alternative first (important for email clients)
            text_content = f"""Reset Your Password - Security Analyzer
            
Hello,

We received a request to reset your password for your Security Analyzer account. To create a new password, please click on the link below:

{reset_url}

If you did not request a password reset, please ignore this email or contact support if you have concerns.

The link will expire in 30 minutes for security reasons.

Best regards,
The Security Analyzer Team

&copy; 2025 Security Analyzer. All rights reserved.
            """
            part1 = MIMEText(text_content, 'plain')
            msg.attach(part1)
            
            # Add HTML content to the email
            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)
            
            # Send email using Gmail SMTP
            logger.info(f"Connecting to {SMTP_SERVER}:{SMTP_PORT}...")
            with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
                server.set_debuglevel(1)  # Enable verbose debug output
                
                # Login to Gmail
                logger.info(f"Logging in as {EMAIL_SENDER}...")
                # Make sure app password has no spaces
                app_password = GMAIL_APP_PASSWORD.replace(" ", "")
                server.login(EMAIL_SENDER, app_password)
                
                # Send the email
                logger.info(f"Sending email to {email}...")
                server.send_message(msg)
                
                logger.info("Email sent successfully via Gmail SMTP")
                return True
                
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication Error: {str(e)}")
            logger.error("This is likely due to an incorrect app password or not having an app password set up.")
            return False
        except Exception as e:
            logger.error(f"Exception when sending email via Gmail SMTP: {str(e)}")
            return False
    except Exception as e:
        logger.error(f"Failed to send password reset email: {str(e)}")
        return False

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        # Check if email exists in database
        user = find_user(email)
        
        if user:
            # Generate a secure token
            token = ts.dumps(email, salt='password-reset-salt')
            
            # Create reset URL with proper encoding
            # The URL needs to be absolute with domain for email links to work
            reset_url = url_for('reset_password', token=token, _external=True)
            
            # Log the generated URL for debugging
            logger.info(f"Generated reset URL: {reset_url}")
            
            # Send password reset email
            email_sent = send_password_reset_email(email, reset_url)
            
            # Only show the reset link in development mode
            if not DEPLOYMENT_MODE:
                flash(f'Use this link to reset your password: <a href="{reset_url}">{reset_url}</a>', 'info')
            
            # Show appropriate message based on email sending status
            if email_sent:
                flash('A password reset link has been sent to your email address. Please check your inbox (and spam folder).', 'success')
            else:
                # If email sending failed, show the reset link even in production as a fallback
                flash(f'Email delivery failed. Use this link to reset your password: <a href="{reset_url}">{reset_url}</a>', 'info')
        else:
            # Don't reveal if email exists or not for security reasons
            flash('If your email exists in our system, you will receive a password reset link shortly.', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Verify token (valid for 30 minutes)
        email = ts.loads(token, salt='password-reset-salt', max_age=1800)
    except SignatureExpired:
        flash('The password reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)
        
        # Find user and update password
        user = find_user(email)
        
        if user:
            # Hash the new password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            
            # Update user password using direct database connection to bypass RLS
            update_data = {'password': hashed_password}
            success = update_user(email, update_data)
            
            if success:
                logger.info(f"Password updated successfully for user: {email}")
                flash('Your password has been updated successfully. You can now log in with your new password.', 'success')
                return redirect(url_for('login'))
            else:
                logger.error(f"Failed to update password for user: {email}")
                flash('Failed to update password. Please try again later.', 'error')
        
        flash('Failed to update password. Please try again.', 'error')
    
    return render_template('reset_password.html', token=token)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', 
                          error_code=404, 
                          error_title="Page Not Found", 
                          error_message="The page you're looking for doesn't exist or has been moved."), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', 
                          error_code=403, 
                          error_title="Forbidden", 
                          error_message="You don't have permission to access this resource."), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', 
                          error_code=500, 
                          error_title="Server Error", 
                          error_message="Something went wrong on our end. Please try again later."), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'user' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    # Simple URL validation
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Placeholder for actual analysis
    # In a real application, you would perform security checks here
    analysis_result = {
        'url': url,
        'safe': True,
        'threats': [],
        'score': 95,
        'timestamp': datetime.datetime.now().isoformat()
    }
    
    # Save scan to database
    scan_data = {
        'user_email': session['user']['email'],
        'url': url,
        'result': analysis_result,
        'timestamp': datetime.datetime.now()
    }
    
    insert_scan(scan_data)
    
    # Update user's security stats
    user = find_user(session['user']['email'])
    if user:
        update_data = {
            'threats_blocked': user.get('threats_blocked', 0) + len(analysis_result.get('threats', [])),
            'security_score': 95  # Placeholder score
        }
        update_user(session['user']['email'], update_data)
    
    return jsonify(analysis_result)

# Configure upload folder for media
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Register the chat blueprint
app.register_blueprint(chat_bp)

# Route for the chat history page
@app.route('/chat_history_page')
def chat_history_page():
    # Check if user is logged in
    if 'user' not in session:
        flash('Please log in to view your chat history', 'error')
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    
    # Handle new conversation request
    if request.args.get('new_conversation') == 'true':
        # Generate new session ID for the conversation
        session_id = str(uuid.uuid4())
        session['current_conversation'] = session_id
        
        # Initialize empty chat list for new conversation
        # Clear any existing chat messages from the session for the new conversation
        session['chats'] = [] 
        
        # Redirect to the main chat page to start the new conversation
        return redirect(url_for('chat'))
    
    # Get all conversations for the user
    from chat import get_user_chats
    conversations = get_user_chats(user_email)
    
    # Get current conversation ID
    current_conversation = session.get('current_conversation')
    
    # Get chats for current conversation
    chats = []
    if current_conversation:
        # Filter chats for current conversation
        chats = [chat for chat in session.get('chats', []) 
                if chat.get('session_id') == current_conversation]
    
    return render_template('chat_history.html', 
                         conversations=conversations,
                         chats=chats,
                         current_conversation=current_conversation,
                         user=session['user'])

# Profile and settings page
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    # Check if user is logged in
    if 'user' not in session:
        flash('Please log in to view your profile', 'error')
        return redirect(url_for('login'))
    
    user_email = session['user']['email']
    
    # Get the current user data
    user_data = find_user(user_email)
    if not user_data:
        flash('User not found', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Check which form was submitted
        if 'update_profile' in request.form:
            # Handle profile update
            name = request.form.get('name')
            bio = request.form.get('bio')
            location = request.form.get('location')
            organization = request.form.get('organization')
            
            # Update user data
            update_data = {
                'name': name,
                'bio': bio,
                'location': location,
                'organization': organization,
                'updated_at': datetime.datetime.now().isoformat()
            }
            
            # Use direct database connection to update user
            success = update_user(user_email, update_data)
            
            if success:
                # Update session data
                session['user']['name'] = name
                flash('Profile updated successfully', 'success')
                # Get updated user data
                user_data = find_user(user_email)
            else:
                flash('Failed to update profile', 'error')
        
        elif 'change_password' in request.form:
            # Handle password change
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            # Validate inputs
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match', 'error')
            else:
                # Verify current password
                is_valid = verify_password(user_email, current_password)
                
                if is_valid:
                    # Hash new password
                    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
                    
                    # Update password in database
                    update_data = {
                        'password': hashed_password,
                        'updated_at': datetime.datetime.now().isoformat()
                    }
                    
                    success = update_user(user_email, update_data)
                    
                    if success:
                        flash('Password changed successfully', 'success')
                    else:
                        flash('Failed to change password', 'error')
                else:
                    flash('Current password is incorrect', 'error')
    
    return render_template('profile.html', user=user_data)

if __name__ == '__main__':
    app.run(debug=True)
