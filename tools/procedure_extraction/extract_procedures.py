import os
import re
import csv
import json
import sys

def extract_procedures_from_readme(filepath):
    """
    Extracts procedures, metadata, and test links from a README.md file.
    Returns a list of dictionaries, one for each procedure.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # extract Metadata
    metadata_match = re.search(r'## Metadata\s*\n+((?:.*\|.*\n)+)', content, re.MULTILINE)
    technique_id = "Unknown"
    external_ids = []

    if metadata_match:
        metadata_table = metadata_match.group(1)
        for line in metadata_table.split('\n'):
            if '|' not in line:
                continue
            cols = [c.strip() for c in line.split('|')]
            if len(cols) < 3:
                continue
            key = cols[1]
            value = cols[2]

            if 'ID' in key and key.strip() == 'ID':
                technique_id = value
            elif 'External IDs' in key:
                ids = re.findall(r'T\d{4}(?:\.\d{3})?', value)
                external_ids.extend(ids)

    primary_external_id = external_ids[0] if external_ids else "Unknown"

    # Scan for reference links
    ref_links = {}
    ref_matches = re.findall(r'^\[(.*?)\]:\s*(.*?)\s*$', content, re.MULTILINE)
    for ref_id, url in ref_matches:
        ref_links[ref_id] = url

    # extract Procedures
    procedures = {}
    procedures_match = re.search(r'## Procedures\s*\n+((?:.*\|.*\n)+)', content, re.MULTILINE)
    if procedures_match:
        procedures_table = procedures_match.group(1)
        lines = procedures_table.split('\n')

        for line in lines:
            if not line.strip():
                continue
            cols = [c.strip() for c in line.split('|')]
            if len(cols) < 4:
                continue

            proc_id = cols[1]
            proc_title = cols[2]

            # Filter garbage rows: Procedure ID must start with TRR
            if not proc_id.startswith('TRR'):
                continue

            procedures[proc_id] = {
                'title': proc_title,
                'test_links': []
            }

    # extract Available Emulation Tests
    tests_match = re.search(r'## Available Emulation Tests\s*\n+((?:.*\|.*\n)+)', content, re.MULTILINE)
    if tests_match:
        tests_table = tests_match.group(1)
        lines = tests_table.split('\n')

        for line in lines:
            if not line.strip():
                continue
            cols = [c.strip() for c in line.split('|')]
            if len(cols) < 3: # | ID | Link |
                continue

            proc_id = cols[1]
            link_md = cols[2]

            if proc_id in procedures:
                procedures[proc_id]['test_links'].append(link_md)

    results = []

    for proc_id, proc_data in procedures.items():
        test_ids_list = []

        full_link_text = ", ".join(proc_data['test_links'])

        link_pattern = re.compile(r'\[([^\]]+)\](?:\(([^)]+)\)|\[([^\]]*)\])?')

        for match in link_pattern.finditer(full_link_text):
            text = match.group(1)
            url_part = match.group(2)
            ref_part = match.group(3)

            link_text = text
            link_url = ""

            if url_part:
                link_url = url_part
            elif ref_part is not None:
                ref = ref_part if ref_part else text
                link_url = ref_links.get(ref, "")
            else:
                if text in ref_links:
                    link_url = ref_links[text]
                else:
                    pass

            # Try to extract T-code from URL
            current_t_code = primary_external_id
            if link_url:
                t_code_match = re.search(r'atomics/(T\d{4}(?:\.\d{3})?)/', link_url, re.IGNORECASE)
                if t_code_match:
                    current_t_code = t_code_match.group(1)

            atomic_match = re.search(r'Atomic Tests?\s*(?:#)?([0-9\-\,\s]+)', link_text, re.IGNORECASE)
            nums_found = []

            if atomic_match:
                nums_str = atomic_match.group(1)
                parts = nums_str.split(',')
                for part in parts:
                    part = part.strip()
                    if '-' in part:
                        try:
                            start, end = map(int, part.split('-'))
                            nums_found.extend(range(start, end + 1))
                        except ValueError:
                            pass
                    else:
                        try:
                            nums_found.append(int(part))
                        except ValueError:
                            pass

            if nums_found:
                for num in nums_found:
                    tid = f"{current_t_code}.AT{num}"
                    if tid not in test_ids_list:
                        test_ids_list.append(tid)
            else:
                if link_url:
                    anchor_match = re.search(r'#atomic-test-(\d+)', link_url, re.IGNORECASE)
                    if anchor_match:
                        num = int(anchor_match.group(1))
                        tid = f"{current_t_code}.AT{num}"
                        if tid not in test_ids_list:
                            test_ids_list.append(tid)

        test_ids_list.sort(key=lambda x: int(x.split('.AT')[-1]) if '.AT' in x else 0)
        test_ids_str = ", ".join(test_ids_list)

        results.append({
            'Technique ID': technique_id,
            'External Technique ID': primary_external_id,
            'Procedure ID': proc_id,
            'Procedure Title': proc_data['title'],
            'Test ID': test_ids_str
        })

    return results

def main():
    root_dir = 'reports'
    csv_file = 'tools/procedure_extraction/procedures.csv'
    json_file = 'tools/procedure_extraction/procedures.json'

    all_procedures = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename.lower() == 'readme.md':
                filepath = os.path.join(dirpath, filename)
                try:
                    procs = extract_procedures_from_readme(filepath)
                    all_procedures.extend(procs)
                except Exception as e:
                    print(f"Error processing {filepath}: {e}", file=sys.stderr)

    all_procedures.sort(key=lambda x: (x['Technique ID'], x['Procedure ID']))

    # Write CSV
    fieldnames = ['Technique ID', 'External Technique ID', 'Procedure ID', 'Procedure Title', 'Test ID']

    with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_procedures)

    print(f"Successfully wrote {len(all_procedures)} procedures to {csv_file}")

    # Write JSON
    with open(json_file, 'w', encoding='utf-8') as jsonfile:
        json.dump(all_procedures, jsonfile, indent=4)

    print(f"Successfully wrote {len(all_procedures)} procedures to {json_file}")

if __name__ == "__main__":
    main()
