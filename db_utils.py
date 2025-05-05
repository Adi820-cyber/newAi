"""
Database utilities for direct PostgreSQL connection
"""
import os
import logging
import psycopg2
import urllib.parse
import bcrypt
import datetime
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# PostgreSQL connection details
DB_USER = "postgres"
DB_PASSWORD = urllib.parse.quote_plus("ASDasd123!@#123asdASD")
DB_HOST = "db.mbmpoizvdpbucnfmkkgw.supabase.co"
DB_PORT = "5432"
DB_NAME = "postgres"
DB_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

def get_db_connection():
    """Get a PostgreSQL database connection"""
    try:
        conn = psycopg2.connect(DB_URL)
        return conn
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}")
        return None

def find_user(email):
    """Find a user by email"""
    conn = get_db_connection()
    if not conn:
        return None
    
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        
        columns = [desc[0] for desc in cursor.description]
        result = cursor.fetchone()
        
        if result:
            # Convert to dictionary
            user = {columns[i]: result[i] for i in range(len(columns))}
            logger.info(f"User found: {email}")
            return user
        else:
            logger.warning(f"User not found: {email}")
            return None
    except Exception as e:
        logger.error(f"Error finding user: {str(e)}")
        return None
    finally:
        conn.close()

def insert_user(user_data):
    """Insert a new user"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Generate password hash if not already hashed
        if 'password' in user_data and not user_data['password'].startswith('$2'):
            user_data['password'] = bcrypt.hashpw(
                user_data['password'].encode('utf-8'), 
                bcrypt.gensalt(12)
            ).decode('utf-8')
        
        # Prepare column names and values
        columns = []
        values = []
        placeholders = []
        
        for key, value in user_data.items():
            columns.append(key)
            values.append(value)
            placeholders.append("%s")
        
        # Create SQL query
        query = f"INSERT INTO users ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        
        cursor.execute(query, values)
        conn.commit()
        logger.info(f"User inserted: {user_data.get('email')}")
        return True
    except Exception as e:
        logger.error(f"Error inserting user: {str(e)}")
        conn.rollback()
        return False
    finally:
        conn.close()

def update_user(email, update_data):
    """Update a user"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Prepare SET clause
        set_clause = []
        values = []
        
        for key, value in update_data.items():
            set_clause.append(f"{key} = %s")
            values.append(value)
        
        # Add email to values
        values.append(email)
        
        # Create SQL query
        query = f"UPDATE users SET {', '.join(set_clause)} WHERE email = %s"
        
        cursor.execute(query, values)
        conn.commit()
        logger.info(f"User updated: {email}")
        return True
    except Exception as e:
        logger.error(f"Error updating user: {str(e)}")
        conn.rollback()
        return False
    finally:
        conn.close()

def verify_password(email, password):
    """Verify a user's password"""
    user = find_user(email)
    if not user:
        logger.warning(f"Password verification failed: User not found: {email}")
        return False
    
    if 'password' not in user or not user['password']:
        logger.error(f"Password verification failed: No password for user: {email}")
        return False
    
    try:
        is_valid = bcrypt.checkpw(
            password.encode('utf-8'), 
            user['password'].encode('utf-8')
        )
        logger.info(f"Password verification for {email}: {'Success' if is_valid else 'Failed'}")
        return is_valid
    except Exception as e:
        logger.error(f"Error verifying password: {str(e)}")
        return False

def insert_chat(chat_data):
    """Insert a chat message"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        
        # Prepare column names and values
        columns = []
        values = []
        placeholders = []
        
        for key, value in chat_data.items():
            # Format datetime objects as strings
            if isinstance(value, datetime.datetime):
                value = value.isoformat()
                
            columns.append(key)
            values.append(value)
            placeholders.append("%s")
        
        # Create SQL query
        query = f"INSERT INTO chats ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"
        
        cursor.execute(query, values)
        conn.commit()
        logger.info(f"Chat inserted for user: {chat_data.get('user_email')}")
        return True
    except Exception as e:
        logger.error(f"Error inserting chat: {str(e)}")
        conn.rollback()
        return False
    finally:
        conn.close()

def get_user_chats(user_email):
    """Get all chats for a user"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        query = "SELECT * FROM chats WHERE user_email = %s ORDER BY created_at DESC"
        cursor.execute(query, (user_email,))
        
        columns = [desc[0] for desc in cursor.description]
        results = cursor.fetchall()
        
        # Convert to list of dictionaries
        chats = []
        for row in results:
            chat = {columns[i]: row[i] for i in range(len(columns))}
            
            # Convert datetime objects to ISO format strings
            if 'created_at' in chat and isinstance(chat['created_at'], datetime.datetime):
                chat['created_at'] = chat['created_at'].isoformat()
                
            chats.append(chat)
        
        logger.info(f"Found {len(chats)} chats for user: {user_email}")
        return chats
    except Exception as e:
        logger.error(f"Error getting user chats: {str(e)}")
        return []
    finally:
        conn.close()

def get_conversation_chats(user_email, session_id):
    """Get all chats for a specific conversation session"""
    conn = get_db_connection()
    if not conn:
        return []
    
    try:
        cursor = conn.cursor()
        # Fetch chats for the specific session, ordered chronologically
        query = "SELECT * FROM chats WHERE user_email = %s AND session_id = %s ORDER BY created_at ASC"
        cursor.execute(query, (user_email, session_id))
        
        columns = [desc[0] for desc in cursor.description]
        results = cursor.fetchall()
        
        # Convert to list of dictionaries
        chats = []
        for row in results:
            chat = {columns[i]: row[i] for i in range(len(columns))}
            
            # Convert datetime objects to ISO format strings if they are datetime objects
            if 'created_at' in chat and isinstance(chat['created_at'], datetime.datetime):
                chat['created_at'] = chat['created_at'].isoformat()
                
            chats.append(chat)
        
        logger.info(f"Found {len(chats)} messages for conversation {session_id} for user: {user_email}")
        return chats
    except Exception as e:
        logger.error(f"Error getting conversation chats: {str(e)}")
        return []
    finally:
        if conn:
            conn.close()
