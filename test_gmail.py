import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import sys

# Gmail credentials
your_email = 'cyberai.help@gmail.com'
# Remove spaces from app password - Google ignores spaces but the code needs them removed
app_password = 'nsxhshgrodjmhgkz'  # App password with spaces removed
recipient_email = 'aditya.pangavhane_24ucs@sanjivani.edu.in'  # Recipient email

def send_test_email():
    print("Starting email test...")
    print(f"From: {your_email}")
    print(f"To: {recipient_email}")
    print("App password length:", len(app_password))
    
    # Create message container
    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'Test Email from Security Analyzer'
    msg['From'] = f"Security Analyzer <{your_email}>"
    msg['To'] = recipient_email
    
    # Create plain text version of the email
    text = """Hello from Security Analyzer!
This is a test email to verify the SMTP configuration.
If you received this, the email setup is working correctly."""
    
    # Create HTML version of the email
    html = """
    <html>
    <body>
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background-color: #4f46e5; padding: 20px; text-align: center;">
                <h1 style="color: white; margin: 0;">Security Analyzer</h1>
            </div>
            <div style="padding: 20px; border: 1px solid #e5e7eb; border-top: none;">
                <h2>Test Email</h2>
                <p>This is a test email from Security Analyzer!</p>
                <p>If you received this, the email configuration is working correctly.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # Attach parts to message
    part1 = MIMEText(text, 'plain')
    part2 = MIMEText(html, 'html')
    msg.attach(part1)
    msg.attach(part2)
    
    try:
        print("Connecting to Gmail SMTP server...")
        # Connect to Gmail's SMTP server
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.set_debuglevel(1)  # Shows detailed debug information
        
        print("Logging in to Gmail...")
        server.login(your_email, app_password)
        
        print("Sending email...")
        server.send_message(msg)
        server.quit()
        
        print("Email sent successfully!")
        return True
    except smtplib.SMTPAuthenticationError as e:
        print(f"Authentication error: {e}")
        print("This is likely due to an incorrect app password or Gmail settings.")
        print("Make sure you have:")
        print("1. Enabled 2-Step Verification in your Google Account")
        print("2. Generated an App Password specifically for this application")
        print("3. Used the correct app password (16 characters, no spaces)")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Gmail SMTP Test")
    print("-" * 50)
    result = send_test_email()
    if result:
        print("\nTest completed successfully!")
        sys.exit(0)
    else:
        print("\nTest failed. Please check the error messages above.")
        sys.exit(1)
