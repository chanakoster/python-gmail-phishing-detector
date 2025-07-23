from email.utils import parseaddr


def extract_sender_name_and_email(from_header):
    print ("🟩Collecting sender email and sender name")
    name, email = parseaddr(from_header or "")
    return name, email