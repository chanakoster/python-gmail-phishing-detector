import json
import os


def load_scanned_email_ids(filename="scanned_ids.json"):
    print ("🗂️Loading scanned email ids")
    if os.path.exists(filename):
        try:
            with open(filename, "r") as file:
                return set(json.load(file))
        except (json.JSONDecodeError, IOError) as e:
            print(f"❌Warning: Failed to load scanned IDs from {filename}: {e}")
            return set()
    return set()


def save_new_scanned_ids(new_ids, filename="scanned_ids.json"):
    print ("🙌Saving new scanned ids")
    existing_ids = set()
    if os.path.exists(filename):
        try:
            with open(filename, "r") as file:
                existing_ids = set(json.load(file))
        except (json.JSONDecodeError, IOError) as e:
            print(f"❌Warning: Failed to load existing IDs before saving: {e}")

    updated_ids = existing_ids.union(new_ids)

    try:
        with open(filename, "w", encoding="utf-8") as file:
            json.dump(list(updated_ids), file)
    except IOError as e:
        print(f"❌Error: Failed to save scanned IDs to {filename}: {e}")
