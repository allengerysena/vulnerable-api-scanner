import subprocess
import argparse
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def send_email(subject, body, recipient_email):
    sender_email = "email@gmail.com"
    sender_password = "abcdefghijklmn"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, recipient_email, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")

def run_script(script_name, file_name):
    command = f"python3 {script_name} -f {file_name}"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode == 0:
        output = stdout.decode()
        print(output)
        return output
    else:
        error_output = stderr.decode()
        print(f"Error in {script_name}:\n{error_output}")
        return error_output

def main(file_name, recipient_email):
    scripts = [
        "tools/detect_hhi.py",
        "tools/detect_lfi.py",
        "tools/detect_rfi.py",
        "tools/detect_sqli.py",
        "tools/detect_ssti.py",
        "tools/detect_xss.py"
    ]

    email_body = ""

    for script in scripts:
        output = run_script(script, file_name)
        email_body += f"{output}"

    current_date = datetime.now().strftime("%Y-%m-%d")
    subject = f"[WARNING] Vulnerability Detected! {current_date}"
    send_email(subject, email_body, recipient_email)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run multiple detection scripts with a specified file.")
    parser.add_argument("-f", "--file", required=True, help="The name of the file to be used by the scripts.")
    parser.add_argument("-e", "--email", required=True, help="The recipient email address.")
    args = parser.parse_args()

    main(args.file, args.email)
