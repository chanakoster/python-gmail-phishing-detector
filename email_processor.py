from gmail_labeling import label_email
from risk_analysis import risk_analysis
from risk_assessment import determine_risk_level

def process_email(email_id, service, email_info):
    print(f"📥 Processing email ID: {email_id}")

    results, vt_reports = risk_analysis(email_info)

    risk_level = determine_risk_level(results)

    label_email(service, email_id, risk_level)

    print("💌Email processed")
    return results, vt_reports, risk_level
