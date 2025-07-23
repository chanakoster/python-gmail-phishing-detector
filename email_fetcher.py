def fetch_unscanned_emails(service, scanned_ids):
    try:
        print ("📂Fetching unread messages")
        results = service.users().messages().list(userId='me',).execute()
        messages = results.get('messages', [])
        messages.reverse()

        unscanned = [msg for msg in messages if msg['id'] not in scanned_ids]
        return unscanned

    except Exception as e:
        print(f"❌Error fetching emails: {e}")
        return []


