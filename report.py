import base64
import json
import os
from datetime import datetime
from email.mime.text import MIMEText
from config import HIGH_RISK_LABEL, LOW_RISK_LABEL


def build_report_data(email_info, vt_reports, risk_level):
    print("🤓 Putting together the JSON report")
    return {
        "vt_reports": vt_reports,
        "risk_level": risk_level,
        "email_id": email_info.get("email_id", ""),
        "gmail_message_id": email_info.get("email_id", ""),
        "date": email_info.get("date", ""),
        "sender_name": email_info.get("sender_name", ""),
        "sender_email": email_info.get("sender_email", ""),
        "subject": email_info.get("subject", ""),
    }


def format_vt_report_html(vt_report, label=None, context_info=None):
    if not isinstance(vt_report, dict):
        return "<p>❌ Invalid VirusTotal report format.</p>"

    attributes = vt_report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", "N/A")

    html_parts = []
    if label:
        html_parts.append(f"<h4>{label}:</h4>")

    if context_info:
        html_parts.append(f"<p><strong>{context_info[0]}:</strong> {context_info[1]}</p>")

    html_parts.append("<ul>")
    html_parts.append(f"<li><strong>Reputation Score:</strong> {reputation}</li>")
    html_parts.append(f"<li><strong>Suspicious detections:</strong> {stats.get('suspicious', 0)}</li>")
    html_parts.append(f"<li><strong>Undetected:</strong> {stats.get('undetected', 0)}</li>")
    html_parts.append("</ul>")

    return "\n".join(html_parts)


def report_html(risk_results, vt_reports, risk_level, email_info):
    print("😎 Putting together the HTML report")

    risk_lines = []
    for risk_dict in risk_results:
        risk_factor = risk_dict.get("risk_factor", "Unknown")
        risk = risk_dict.get("risk", "Pass")
        risk_lines.append(f"<li><strong>{risk_factor}:</strong> {risk}</li>")
    risk_factors_html = "<ul>" + "".join(risk_lines) + "</ul>" if risk_lines else "<p>No risks detected.</p>"

    vt_html = ""
    if vt_reports:
        for factor, reports_list in vt_reports.items():
            if not reports_list or all(not bool(report) for report in reports_list):
                continue

            if factor.lower() == "domain":
                for vt_report in reports_list:
                    vt_html += format_vt_report_html(
                        vt_report,
                        label="VirusTotal Report for Email domain"
                    )
            elif factor.lower() == "urls":
                for url_report in reports_list:
                    url = url_report.get("meta", {}).get("url_info", {}).get("url", "Unknown URL")
                    vt_html += format_vt_report_html(
                        url_report,
                        label="VirusTotal Report for Urls",
                        context_info=("URL", url)
                    )
            elif factor.lower() == "attachments":
                for att_report in reports_list:
                    filename = att_report.get("meta", {}).get("file_info", {}).get("name", "Unknown file")
                    vt_html += format_vt_report_html(
                        att_report,
                        label="VirusTotal Report for Attachments",
                        context_info=("Filename", filename)
                    )
            elif factor.lower() == "qr_codes":
                for qr_report in reports_list:
                    file = qr_report.get("meta", {}).get("qr_info", {}).get("filename", "Unknown file")
                    vt_html += format_vt_report_html(
                        qr_report,
                        label="VirusTotal Report for QR Codes",
                        context_info=("QR Code found in", file)
                    )

    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; font-size: 14px; color: #333;">
        <h2>CK Email Scanner Report</h2>
        <p><strong>Email ID:</strong> {email_info.get('email_id', 'N/A')}</p>
        <p><strong>Date:</strong> {email_info.get('date', 'N/A')}</p>
        <p><strong>From:</strong> {email_info.get('sender_name', 'N/A')} &lt;{email_info.get('sender_email', 'N/A')}&gt;</p>
        <p><strong>Subject:</strong> {email_info.get('subject', 'N/A')}</p>

        <h3>Risk Level: {risk_level}</h3>
        <h3>Risk Factors:</h3>
        {risk_factors_html}
        <h3>VirusTotal Reports:</h3>
        {vt_html}
    </body>
    </html>
    """


def format_vt_report_text(vt_report, label=None, context_info=None):
    if not isinstance(vt_report, dict):
        return "❌ Invalid VirusTotal report format.\n"

    attributes = vt_report.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", "N/A")

    lines = []
    if label:
        lines.append(f"{label}:")

    if context_info:
        lines.append(f"{context_info[0]}: {context_info[1]}")

    lines.append(f"Reputation Score: {reputation}")
    lines.append(f"Suspicious detections: {stats.get('suspicious', 0)}")
    lines.append(f"Undetected: {stats.get('undetected', 0)}")

    return "\n".join(lines) + "\n"


def save_report_to_file(report_data, base_folder="reports"):
    print("📝 Saving report to file")
    risk_level = report_data.get("risk_level", "none")

    if risk_level not in ("high risk", "low risk"):
        folder_name = "No risk"
    else:
        folder_name = risk_level.replace(" risk", "")

    folder_path = os.path.join(base_folder, f"{folder_name}_risk")
    os.makedirs(folder_path, exist_ok=True)

    msg_id = report_data.get("gmail_message_id", f"unknown_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    filename = f"{msg_id}.json"
    file_path = os.path.join(folder_path, filename)

    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=2, ensure_ascii=False)

    print(f"✅ Report saved to: {file_path}")


def email_report(service, risk_results, vt_reports, risk_level, email_info):
    print("📤 Emailing the report")
    report_text = report_html(risk_results, vt_reports, risk_level, email_info)
    subject = email_info.get("subject", "")

    if risk_level == "HIGH RISK":
        prefix = f"{HIGH_RISK_LABEL} Alert"
    elif risk_level == "LOW RISK":
        prefix = f"{LOW_RISK_LABEL} Alert"
    else:
        prefix = "Safe"

    my_email = service.users().getProfile(userId='me').execute()['emailAddress']
    subject_text = f"{prefix} - [{subject[:50]}]"

    message = MIMEText(report_text, "html")
    message['to'] = my_email
    message['from'] = my_email
    message['subject'] = subject_text

    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    request_body = {'raw': raw}

    service.users().messages().send(userId='me', body=request_body).execute()
    print(f"📧 Report email sent: {subject_text}")