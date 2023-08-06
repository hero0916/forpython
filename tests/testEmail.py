# import smtplib
# from email.mime.text import MIMEText

# # Set up the connection to the SMTP server

# smtp_server = 'smtp.elasticemail.com'
# smtp_port = 2525

# username = 'Fern08999@outlook.com'
# password = 'EEF4DEEEA82B160ADDABC7F094A3B1CA3EBD'

# # Create a secure connection to the server
# server = smtplib.SMTP(smtp_server, smtp_port, local_hostname='svenostermann.pythonanywhere')
# server.starttls()

# # Log in to your account
# server.login(username, password)

# # Compose the email message
# sender = 'kanedakenji646@gmail.com'
# recipient = 'svenostermann2023@outlook.com'
# subject = 'Test Email'
# message = 'This is a test email sent from Python.'

# msg = MIMEText(message)
# msg['Subject'] = subject
# msg['From'] = sender
# msg['To'] = recipient

# # Send the email
# server.sendmail(sender, recipient, msg.as_string())

# # Close the connection
# server.quit()

import requests

api_key = '2C9C8BBFD3DC6AA087A129246E8BA853347334734CB4A3485443B63FB9954A8F0AAE9511132E84239CDA40B05079D2AF'
sender = 'kanedakenji646@gmail.com'
recipient = 'kanedakenji646@gmail.com'
subject = 'Hello from Elastic Email API'
body = 'This is the email body.'

payload = {
    'apikey': api_key,
    'from': sender,
    'to': recipient,
    'subject': subject,
    'bodyHtml': body
}

response = requests.post('https://api.elasticemail.com/v2/email/send', data=payload)

if response.status_code == 200:
    print('Email sent successfully!')
else:
    print('Failed to send email. Error:', response.text)