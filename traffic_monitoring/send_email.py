import smtplib, ssl, sys
from email.mime.multipart import MIMEMultipart 
from email.mime.text import MIMEText 
from email.mime.base import MIMEBase 
from email import encoders 

filename = sys.argv[1]

# Create a secure SSL context
context = ssl.create_default_context()
port = 465  # For SSL

fromaddr = "reverse.traceroute@gmail.com" 
password = "" # Temporary: Removed.

toaddr = "egurmeri@gmail.com"

# instance of MIMEMultipart 
msg = MIMEMultipart() 

# storing the senders email address 
msg['From'] = fromaddr 

# storing the receivers email address 
msg['To'] = toaddr 

# storing the subject 
msg['Subject'] = "Network Traffic Digest."

# string to store the body of the mail 
body = "Latest Docker container network traffic capture attached below."

# attach the body with the msg instance 
msg.attach(MIMEText(body, 'plain')) 

# open the file to be sent 
attachment = open(filename, "rb") 

# instance of MIMEBase and named as p 
p = MIMEBase('application', 'octet-stream') 

# To change the payload into encoded form 
p.set_payload((attachment).read()) 

# encode into base64 
encoders.encode_base64(p) 

p.add_header('Content-Disposition', "attachment; filename= %s" % filename) 

# attach the instance 'p' to instance 'msg' 
msg.attach(p) 

with smtplib.SMTP_SSL("smtp.gmail.com", port, context=context) as s:
	# Authentication 
	s.login(fromaddr, password) 

	# Converts the Multipart msg into a string 
	text = msg.as_string() 

	# sending the mail 
	s.sendmail(fromaddr, toaddr, text) 
