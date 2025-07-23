import re
import language_tool_python
from fuzzywuzzy import fuzz
from all_email_info import extract_qr_from_attachment
from virustotal import get_domain_report, get_url_report, submit_url, upload_file, get_file_report
from difflib import SequenceMatcher
from textblob import TextBlob

def check_email_domain(email_address):
    risk_factor = "Email domain"
    risk = "Risk not detected"
    print(f"➡️Checking {risk_factor}")

    domain = email_address.split("@")[-1].lower().strip()
    print (f"🔵{domain}")

    vt_report = get_domain_report(domain)
    if not vt_report:
        return {"risk_factor": risk_factor, "risk": risk,
            "vt_report": [{
                **vt_report,
                "meta": {
                    "domain_info": {
                        "domain": domain
                    }
                }
            }]
        }
    attributes = vt_report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", 0)
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    if domain == "gmail.com":    #whitelist
        risk = "Risk not detected"
    elif malicious > 0:
        risk = "high"
    elif suspicious > 0 or reputation < 0:
        risk = "low"

    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": [vt_report]
        }


def check_urls_in_email(urls):
    risk_factor = "Urls"
    risk = "Risk not detected"
    vt_reports = []

    print(f"➡️Checking {risk_factor}")

    if not urls:
        print("✖️No URLs in email.")
        return {
            "risk_factor": risk_factor,
            "risk": "No URLs found",
            "vt_report": []
        }

    for url in urls:
        print(f"📎{url}")
        scan_id = submit_url(url)
        if not scan_id:
            continue

        vt_report = get_url_report(scan_id)
        if not vt_report:
            continue

        stats = vt_report.get("data", {}).get("attributes", {}).get("stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            risk = "high"
        elif suspicious > 0 and risk != "high":
            risk = "low"

        vt_reports.append({
            **vt_report,
            "meta": {
                "url_info": {
                    "url": url
                }
            }
        })
    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_reports
            }


def check_attachments(attachments):
    risk_factor = "Attachments"
    risk = "Risk not detected"
    vt_reports = []

    print(f"➡️ Checking {risk_factor}")

    if not attachments:
        print("✖️No attachments found")
        return {
            "risk_factor": risk_factor,
            "risk": "No Attachments found",
            "vt_report": vt_reports
        }

    for attachment in attachments:
        print(f"🔍 Scanning attachment... {attachment.get('filename', 'Unnamed')}")
        filename = attachment.get("filename", "Unnamed")
        data = attachment.get("data")
        if not data:
            continue

        file_id = upload_file(data)
        if not file_id:
            continue

        vt_report = get_file_report(file_id)
        if not vt_report:
            continue

        vt_reports.append({
            **vt_report,
            "meta": {
                "file_info": {
                    "name": filename
                }
            }
        })
        stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats.get("malicious", 0) > 0:
            risk = "high"
            break
        elif stats.get("suspicious", 0) > 0 and risk != "high":
            risk = "low"

    print (f"☑️{risk_factor}: {risk}")
    return {
        "risk_factor": risk_factor,
        "risk": risk,
        "vt_report": vt_reports
    }


def check_qr_codes(attachments):
    risk_factor = "QR codes"
    risk = "Risk not detected"
    vt_reports = []

    print(f"➡️Checking {risk_factor}")

    for idx, attachment in enumerate(attachments):
        b64_data = attachment.get("data")
        filename = attachment.get("filename", f"attachment_{idx}")
        if not b64_data:
            continue

        try:
            qr_url = extract_qr_from_attachment(b64_data)
            if not qr_url:
                continue


            vt_qr_code_id = submit_url(qr_url)
            vt_report = get_url_report(vt_qr_code_id)
            if not vt_report:
                continue

            vt_reports.append({
                "filename": filename,
                "qr_url": qr_url,
                "vt_report": vt_report
            })

            stats = vt_report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if stats.get("malicious", 0) > 0:
                risk = "high"
                break
            elif stats.get("suspicious", 0) > 0 and risk != "high":
                risk = "low"

        except Exception as e:
            print(f"❌ Error processing QR code in {filename}: {e}")
            continue

    if not vt_reports:
        print("✖️No QR codes found")
        return {
            "risk_factor": risk_factor,
            "risk": "No QR codes",
            "vt_report": vt_reports
        }

    print (f"☑️{risk_factor}: {risk}")
    return {
        "risk_factor": risk_factor,
        "risk": risk,
        "vt_report": vt_reports
    }


def check_similar_email_address(email_address, known_senders, threshold=0.85):
    #Checks if a sender's email address is similar to previous sender's email address
    risk_factor = "Similar email address"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    for known_email in known_senders:
        if (SequenceMatcher(None, email_address.lower(), known_email.lower()).ratio() >= threshold and
                email_address.lower() != known_email.lower()):
            risk = "very low"
            break

    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_report
        }


def check_sender_name(sender_name, sender_email, known_senders, threshold=0.85):
    #Checks if the senders name is the same/similar to a previous sender but uses a different email address
    risk_factor = "Sender name"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    for known_email, known_name in known_senders.items():
        similarity = SequenceMatcher(None, sender_name.lower(), known_name.lower()).ratio()
        if similarity > threshold and sender_email.lower() != known_email.lower():
            risk = "very low"
            break

    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_report
        }


def check_for_urgency(email_content):
    risk_factor = "Urgency"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    urgent_words = [
        "urgent", "immediately", "asap", "attention", "important",
        "act now", "response needed", "deadline", "alert", "emergency"
    ]
    patterns = [
        r"respond (immediately|asap|now)",
        r"urgent (request|matter|issue)",
        r"reply by \d{1,2} (hours|days)",
        r"action required",
        r"deadline.*\d{1,2} (hours|days|minutes)"
    ]
    content_lower = email_content.lower()
    if any(word in content_lower for word in urgent_words) or any(re.search(p, content_lower) for p in patterns):
        risk = "very low"

    blob = TextBlob(email_content)
    polarity = blob.sentiment.polarity
    subjectivity = blob.sentiment.subjectivity

    if subjectivity > 0.5 and polarity < 0:
        if risk == "very low":
            risk = "low"
        elif risk == "Risk not detected":
            risk = "very low"

    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_report
        }


def check_for_grammar_errors(email_content):
    risk_factor = "Grammar errors"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    tool = language_tool_python.LanguageTool('en-US')
    try:
        matches = tool.check(email_content)
        if len(matches) > 10:
            risk = "very low"
    except Exception as e:
        print(f"❌ Grammar tool error: {e}")

    tool.close()
    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_report
        }


def check_for_generic_greetings(email_content):
    risk_factor = "Generic greeting"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    greetings = [
        "dear customer", "dear user", "dear sir", "dear madam", "hello", "hi",
        "greetings", "to whom it may concern", "dear friend", "dear valued customer"
    ]
    content = email_content[:200].strip().lower()
    if any(re.match(rf"^{re.escape(g)}[,\n\s]", content) for g in greetings):
        risk = "very low"

    print (f"☑️{risk_factor}: {risk}")
    return {
            "risk_factor": risk_factor,
            "risk": risk,
            "vt_report": vt_report
        }


def check_for_request_of_sensitive_info(email_content):
    risk_factor = "Request of sensitive info"
    risk = "Risk not detected"
    vt_report = []

    print(f"➡️Checking {risk_factor}")

    sensitive_phrases = [
        "provide your password",
        "send your login details",
        "submit your credit card information",
        "update your billing information",
        "confirm your payment details",
        "submit your social security number",
        "send a copy of your id",
        "provide your phone number",
        "enter your security code",
        "submit your personal information",
        "verify your payment method",
        "share your credentials",
        "we need your ssn",
        "confirm your credit card",
        "identity verification required",
        "reset your password here",
        "verify your account details"
    ]

    email_lower = email_content.lower()

    for phrase in sensitive_phrases:
        phrase_lower = phrase.lower()
        if phrase_lower in email_lower:
            risk = "very low"
            break
        elif fuzz.partial_ratio(phrase_lower, email_lower) > 85:
            risk = "very low"
            break

    print(f"☑️{risk_factor}: {risk}")
    return {
        "risk_factor": risk_factor,
        "risk": risk,
        "vt_report": vt_report
    }


def risk_analysis(email_info):
    print("😐 Starting risk analysis")

    sender_email = email_info["sender_email"]
    urls = email_info["urls"]
    attachments = email_info["attachments"]
    attachments_for_qr_codes = email_info["attachments"]
    sender_name = email_info["sender_name"]
    known_senders = email_info["known_senders"]
    email_content = email_info["email_content"]

    results = []
    vt_reports = {}

    checks = [
        check_email_domain(sender_email),
        check_urls_in_email(urls),
        check_attachments(attachments),
        check_qr_codes(attachments_for_qr_codes),
        check_similar_email_address(sender_email, known_senders),
        check_sender_name(sender_name, sender_email, known_senders),
        check_for_urgency(email_content),
        check_for_grammar_errors(email_content),
        check_for_generic_greetings(email_content),
        check_for_request_of_sensitive_info(email_content),
    ]

    for result in checks:
        if not isinstance(result, dict):
            continue  # safety check

        risk_factor = result.get("risk_factor", "Unknown")
        risk = result.get("risk", "Risk not detected")
        vt_data = result.get("vt_report")

        results.append({
            "risk_factor": risk_factor,
            "risk": risk
        })

        if isinstance(vt_data, list):  # ← This allows empty lists like []
            vt_reports[risk_factor] = vt_data
        elif isinstance(vt_data, dict):  # ← This allows empty dicts like {}
            vt_reports[risk_factor] = [vt_data]
        elif vt_data:  # ← Only skips falsy values like None or ""
            vt_reports[risk_factor] = [vt_data]

    print("🙂Risk analysis complete")
    return results, vt_reports