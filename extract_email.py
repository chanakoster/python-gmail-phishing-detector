def extract_email_info(email_id, service):
    print("🟦Collecting email id, payload, subject, date, and from header")
    msg = service.users().messages().get(userId="me", id=email_id, format="full").execute()
    payload = msg.get("payload", {})
    headers = payload.get("headers", [])
    subject = next((h["value"] for h in headers if h["name"].lower() == "subject"), "(no subject)")
    from_header = next((h["value"] for h in headers if h["name"].lower() == "from"), "unknown")
    date_header = next((h["value"] for h in headers if h["name"].lower() == "date"), "")

    return {
        "email_id": email_id,
        "payload": payload,
        "subject": subject,
        "date": date_header,
        "from_header": from_header,
    }