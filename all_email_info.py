import re
import io
import base64
from extract_email import extract_email_info
from PIL import Image
from bs4 import BeautifulSoup
from pyzbar.pyzbar import decode
from email.utils import parseaddr
from known_senders import extract_previous_senders, save_known_senders


def extract_urls_from_email(email_info):
    print ("🟨Collecting URLs")
    html = email_info.get("html_body", "")
    text = email_info.get("plain_body", "")
    urls = set()

    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all(True):
            for attr in ["href", "src", "action", "data", "poster"]:
                if tag.has_attr(attr):
                    urls.add(tag[attr])
        urls.update(re.findall(r'https?://[^\s\'"<>]+', html))

    if text:
        urls.update(re.findall(r'https?://[^\s\'"<>]+', text))
    return list(urls)


def extract_email_content(payload):
    print ("⬜Collecting plain email content and html email content")
    plain_text = ""
    html_text = ""

    mime_type = payload.get("mimeType", "")
    body = payload.get("body", {})

    if mime_type == "text/plain" and "data" in body:
        decoded = base64.urlsafe_b64decode(body["data"]).decode("utf-8", errors="replace")
        plain_text += decoded

    elif mime_type == "text/html" and "data" in body:
        decoded = base64.urlsafe_b64decode(body["data"]).decode("utf-8", errors="replace")
        html_text += decoded

    elif "parts" in payload:
        for part in payload["parts"]:
            parts = extract_email_content(part)
            plain_text += parts.get("plain", "")
            html_text += parts.get("html", "")

    return {
        "plain": plain_text.strip(),
        "html": html_text.strip()
    }


def extract_attachments_metadata(payload):
    print ("🟧Collecting attachment data")
    attachments = []

    if "parts" in payload:
        for part in payload["parts"]:
            attachments += extract_attachments_metadata(part)
    else:
        filename = payload.get("filename", "")
        body = payload.get("body", {})
        if filename and "attachmentId" in body:
            attachments.append({
                "filename": filename,
                "mimeType": payload.get("mimeType"),
                "size": body.get("size"),
                "attachmentId": body.get("attachmentId")
            })
    print(f"🟠There are {len(attachments)} attachments")
    return attachments


def extract_qr_from_attachment(decoded_bytes):
    try:
        image = Image.open(io.BytesIO(decoded_bytes))
        qr_codes = decode(image)
        if qr_codes:
            return qr_codes[0].data.decode("utf-8")
    except Exception as e:
        print(f"❌ Error reading QR code: {e}")
    return None


def fetch_and_decode_attachments(service, email_id, attachments_meta):
    print("🟥Collecting attachments")
    attachments = []

    for att in attachments_meta:
        att_id = att.get("attachmentId")
        if not att_id:
            continue

        try:
            att_data = service.users().messages().attachments().get(
                userId="me",
                messageId=email_id,
                id=att_id
            ).execute()

            data = att_data.get("data")
            if not data:
                continue

            decoded_data = base64.urlsafe_b64decode(data)

            attachments.append({
                "filename": att.get("filename"),
                "mimeType": att.get("mimeType"),
                "size": att.get("size"),
                "data": decoded_data
            })

        except Exception as e:
            print(f"❌Error downloading attachment '{att.get('filename')}': {e}")
            continue
    print (f"🔴There are {len(attachments)} attachments")
    return attachments


def extract_attachments(parts):
    attachments = []
    for part in parts:
        if not isinstance(part, dict):
            print(f"Warning: Part is not a dict: {part}")
            continue

        if part.get("filename"):  # filename present means it's an attachment or inline file
            att = {
                "filename": part["filename"],
                "mimeType": part.get("mimeType"),
                "attachmentId": part.get("body", {}).get("attachmentId"),
                "size": part.get("body", {}).get("size"),
            }
            attachments.append(att)

        if part.get("parts"):
            attachments += extract_attachments(part["parts"])
    return attachments

def all_email_info(service, email_id, scanned_ids):
    print("🤗Collecting email info")
    email_info = extract_email_info(email_id, service)

    from_header = email_info["from_header"]
    sender_name, sender_email = parseaddr(from_header or "")
    subject = email_info["subject"]
    date = email_info["date"]
    payload = email_info["payload"]

    known_senders = extract_previous_senders(service, scanned_ids)
    save_known_senders(known_senders, filename="known_senders.json")

    body_parts = extract_email_content(payload)
    plain_text = body_parts.get("plain", "")
    html_text = body_parts.get("html", "")
    html_text_clean = BeautifulSoup(html_text, "html.parser").get_text()
    email_content = plain_text + "\n\n" + html_text_clean

    urls = extract_urls_from_email({"html_body": html_text,"plain_body": plain_text})

    attachments_meta = extract_attachments_metadata(payload)
    attachments = fetch_and_decode_attachments(service, email_id, attachments_meta)

    return {
        "email_id": email_id,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "date": date,
        "subject": subject,
        "plain_text": plain_text,
        "html_text": html_text,
        "attachments": attachments,
        "known_senders": known_senders,
        "urls": urls,
        "email_content": email_content
    }
