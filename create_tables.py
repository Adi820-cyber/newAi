import os
import requests
import json
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt

# Initialize bcrypt for password hashing
bcrypt = Bcrypt()

# Load environment variables
load_dotenv()

# Get Supabase credentials
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_SERVICE_KEY')  # Use service key for admin operations

if not supabase_url or not supabase_key:
    print("Error: Supabase URL or key not found in environment variables")
    exit(1)

print(f"Connecting to Supabase at: {supabase_url}")

# Function to execute SQL directly via the REST API
def execute_sql(sql):
    headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(
            f"{supabase_url}/rest/v1/",
            headers=headers,
            data=sql
        )
        
        print(f"SQL execution response: {response.status_code}")
        print(f"Response body: {response.text}")
        
        return response.status_code < 300
    except Exception as e:
        print(f"Error executing SQL: {str(e)}")
        return False

# Create users table
users_table_sql = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    security_score INTEGER DEFAULT 0,
    passwords_protected INTEGER DEFAULT 0,
    threats_blocked INTEGER DEFAULT 0
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow public read access to users" ON users;
DROP POLICY IF EXISTS "Allow public insert access to users" ON users;
DROP POLICY IF EXISTS "Allow public update access to users" ON users;

CREATE POLICY "Allow public read access to users" ON users FOR SELECT USING (true);
CREATE POLICY "Allow public insert access to users" ON users FOR INSERT WITH CHECK (true);
CREATE POLICY "Allow public update access to users" ON users FOR UPDATE USING (true);
"""

# Create scans table
scans_table_sql = """
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_email VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    result JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Allow public read access to scans" ON scans;
DROP POLICY IF EXISTS "Allow public insert access to scans" ON scans;

CREATE POLICY "Allow public read access to scans" ON scans FOR SELECT USING (true);
CREATE POLICY "Allow public insert access to scans" ON scans FOR INSERT WITH CHECK (true);
"""

# Create test user function
def create_test_user():
    # Create a test user with bcrypt hashed password
    password = "test123"
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    test_user_sql = f"""
    INSERT INTO users (email, password, name)
    VALUES ('test@example.com', '{hashed_password}', 'Test User')
    ON CONFLICT (email) DO NOTHING;
    """
    
    if execute_sql(test_user_sql):
        print("Test user created or already exists")
        print("Test user credentials: email=test@example.com, password=test123")
    else:
        print("Failed to create test user")

# Main execution
print("Creating database tables...")

if execute_sql(users_table_sql):
    print("Users table created successfully")
else:
    print("Failed to create users table")

if execute_sql(scans_table_sql):
    print("Scans table created successfully")
else:
    print("Failed to create scans table")

create_test_user()

print("Database setup completed")
