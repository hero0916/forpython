import smtplib
from email.mime.text import MIMEText

# Set up the connection to the SMTP server
smtp_server = 'smtp-mail.outlook.com'
smtp_port = 587

username = 'svenostermann2023@outlook.com'
password = 'hero0916'

# Create a secure connection to the server
server = smtplib.SMTP(smtp_server, smtp_port)
server.starttls()

# Log in to your account
server.login(username, password)

# Compose the email message
sender = 'svenostermann2023@outlook.com'
recipient = 'svenostermann2023@outlook.com'
subject = 'Test Email'
message = 'This is a test email sent from Python.'

msg = MIMEText(message)
msg['Subject'] = subject
msg['From'] = sender
msg['To'] = recipient

# Send the email
server.sendmail(sender, recipient, msg.as_string())

# Close the connection
server.quit()