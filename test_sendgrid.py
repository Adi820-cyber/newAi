import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Test SendGrid email sending
def test_sendgrid():
    # Configure the email content
    message = Mail(
        from_email=('', 'Security Analyzer'),
        to_emails='aditya.pangavhane_24ucs@sanjivani.edu.in',  # Replace with your email
        subject='Test Email from Security Analyzer',
        html_content='<strong>This is a test email from Security Analyzer!</strong>'
    )
    
    try:
        # Get API key from environment
        sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
        
        # Send the email
        response = sg.send(message)
        
        # Print response details
        print(f"Status Code: {response.status_code}")
        print(f"Response Body: {response.body}")
        print(f"Response Headers: {response.headers}")
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error sending email: {e}")

if __name__ == "__main__":
    # Set the SendGrid API key from .env
    os.environ['SENDGRID_API_KEY'] = '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'
    
    # Run the test
    test_sendgrid()
import smtplib
from email.message import EmailMessage

your_email = 'cyberai.help@gmail.com'
app_password = 'Aditya@123'  # NOT your normal password!

def send_email():
    msg = EmailMessage()
    msg['Subject'] = 'Test Email'
    msg['From'] = 'cyberai.help@gmail.com'
    msg['To'] = 'aditya.pangavhane_24ucs@sanjivani.edu.in'
    msg.set_content('Hello from Python!')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.set_debuglevel(1)  # 🔍 Shows what's happening
            smtp.login(cyberai.help@gmail.com, aditya@123)
            smtp.send_message(msg)
            print("✅ Email sent successfully!")
    except Exception as e:
        print("❌ Failed:", e)

send_email()
