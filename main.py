from all_email_info import all_email_info
from email_fetcher import fetch_unscanned_emails
from email_processor import process_email
from gmail_authenticate import gmail_authenticate
from report import email_report, save_report_to_file, build_report_data
from scanned_emails import load_scanned_email_ids, save_new_scanned_ids
from googleapiclient.discovery import build


def main():
    creds = gmail_authenticate()
    service = build("gmail", "v1", credentials=creds)

    scanned_ids = load_scanned_email_ids()

    unscanned_emails = fetch_unscanned_emails(service, scanned_ids)

    if not unscanned_emails:
        print ("📁No unscanned messages")
        return

    for message in unscanned_emails:
        email_id = message['id']

        email_info = all_email_info(service, email_id, scanned_ids)

        risk_results, vt_reports, risk_level= process_email(email_id, service, email_info)

        report_json = build_report_data(email_info, vt_reports, risk_level)

        save_report_to_file(report_json)
        email_report(service, risk_results, vt_reports, risk_level, email_info)

        scanned_ids.add(email_id)
        save_new_scanned_ids(scanned_ids)


if __name__ == "__main__":
    main()