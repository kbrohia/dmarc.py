import os
import shutil
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime
import csv

def parse_dmarc_xmls(input_dir, csv_path, verbose=False):
    parsed_dir = os.path.join(input_dir, "_parsed")
    os.makedirs(parsed_dir, exist_ok=True)

    csv_fields = [
        "report_id", "org_name", "begin_date", "end_date",
        "source_ip", "count", "disposition", "dkim", "spf"
    ]

    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields)
            writer.writeheader()

    for filename in os.listdir(input_dir):
        if filename.endswith(".xml"):
            filepath = os.path.join(input_dir, filename)
            try:
                tree = ET.parse(filepath)
                root = tree.getroot()
                print(f"Processing: {filename}")
                print(f"Root tag: {root.tag}")
                for child in root:
                    print(f"  Child tag: {child.tag}")
                metadata = root.find("report_metadata")
                if metadata is None:
                    print("No <report_metadata> found!")
                    continue

                org_name = metadata.findtext("org_name")
                report_id = metadata.findtext("report_id")
                begin_elem = metadata.find("date_range/begin")
                end_elem = metadata.find("date_range/end")
                if begin_elem is None or end_elem is None:
                    print("Date range missing!")
                    continue

                begin_date = datetime.utcfromtimestamp(int(begin_elem.text)).isoformat()
                end_date = datetime.utcfromtimestamp(int(end_elem.text)).isoformat()

                record_found = False
                for record in root.findall("record"):
                    record_found = True
                    row = record.find("row")
                    if row is None:
                        continue

                    ip = row.findtext("source_ip")
                    count = row.findtext("count")
                    policy = row.find("policy_evaluated")
                    disposition = policy.findtext("disposition") if policy is not None else None
                    dkim = policy.findtext("dkim") if policy is not None else None
                    spf = policy.findtext("spf") if policy is not None else None

                    # Append this record to the CSV file
                    with open(csv_path, "a", newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=csv_fields)
                        writer.writerow({
                            "report_id": report_id,
                            "org_name": org_name,
                            "begin_date": begin_date,
                            "end_date": end_date,
                            "source_ip": ip,
                            "count": count,
                            "disposition": disposition,
                            "dkim": dkim,
                            "spf": spf,
                        })

                if not record_found:
                    print("No <record> tags found.")

                shutil.move(filepath, os.path.join(parsed_dir, filename))
                if verbose:
                    print(f"Parsed and moved: {filename}")

            except Exception as e:
                print(f"Error parsing {filename}: {e}")
def main():
    parser = argparse.ArgumentParser(description="DMARC Aggregate Report Parser")
    parser.add_argument("--path", required=True, help="Path to folder containing DMARC XMLs")
    parser.add_argument("--csv", default="dmarc_parsed.csv", help="CSV output file path")
    parser.add_argument("--verbose", action="store_true", help="Print progress messages")
    args = parser.parse_args()
    parse_dmarc_xmls(args.path, args.csv, args.verbose)

if __name__ == "__main__":
    main()
