from config import HIGH_RISK_LABEL, LOW_RISK_LABEL

def get_label_id(service, label_name: str, create_if_missing: bool = False) -> str | None:
    response = service.users().labels().list(userId="me").execute()
    for label in response.get("labels", []):
        if label["name"].lower() == label_name.lower():
            return label["id"]

    color_settings = {}
    if "high risk" in label_name.lower():
        color_settings = {
            "backgroundColor": "#fb4c2f",  # red
            "textColor": "#ffffff"         # white
        }
    elif "low risk" in label_name.lower():
        color_settings = {
            "backgroundColor": "#fad165",  # yellow
            "textColor": "#000000"         # black
        }

    if create_if_missing:
        label_body = {
            "name": label_name,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }

        if color_settings:
            label_body["color"] = color_settings

        new_label = service.users().labels().create(userId="me", body=label_body).execute()
        return new_label["id"]

    return None

def label_email(service, email_id: str, risk_level: str):
    print ("🏷️Labeling email")
    if risk_level == "HIGH RISK":
        label_name = HIGH_RISK_LABEL
    elif risk_level == "LOW RISK":
        label_name = LOW_RISK_LABEL
    else:
        return

    label_id = get_label_id(service, label_name, create_if_missing=True)
    if not label_id:
        print(f"❌ Failed to apply label for {risk_level}")
        return

    service.users().messages().modify(
        userId='me',
        id=email_id,
        body={
            'addLabelIds': [label_id],
            'removeLabelIds': ['INBOX']
        }
    ).execute()