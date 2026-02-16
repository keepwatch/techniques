import requests
import json
import os
import sys
import statistics

# Configuration
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
TRR_INDEX_PATH = "index.json"
REPORT_PATH = "reports/coverage_analysis.md"

def fetch_attack_data():
    """Fetches the MITRE ATT&CK Enterprise JSON."""
    print(f"Fetching ATT&CK data from {ATTACK_URL}...")
    try:
        response = requests.get(ATTACK_URL)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching ATT&CK data: {e}")
        sys.exit(1)

def parse_attack_data(data):
    """
    Parses the ATT&CK STIX bundle.
    Returns:
        techniques: dict mapping T-code to info {name, platforms, procedure_count, tactics}
    """
    objects = data.get("objects", [])

    # Map STIX ID to T-code for techniques
    stix_id_to_tcode = {}
    techniques = {}

    # First pass: identify techniques
    for obj in objects:
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False):
            stix_id = obj["id"]
            # Extract T-code
            t_code = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    t_code = ref.get("external_id")
                    break

            if t_code:
                stix_id_to_tcode[stix_id] = t_code
                techniques[t_code] = {
                    "name": obj.get("name"),
                    "platforms": obj.get("x_mitre_platforms", []),
                    "tactics": [phase["phase_name"] for phase in obj.get("kill_chain_phases", []) if phase["kill_chain_name"] == "mitre-attack"],
                    "procedure_count": 0,
                    "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
                }

    # Second pass: count procedure examples (relationships)
    # Procedures are relationships where source is (tool, malware, intrusion-set) and target is technique
    # AND relationship_type is 'uses'
    # Actually, ATT&CK "Procedure Examples" are specifically relationships where the description usually describes the procedure.
    # We count all 'uses' relationships targeting the technique.

    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses":
            target_ref = obj.get("target_ref")
            if target_ref in stix_id_to_tcode:
                t_code = stix_id_to_tcode[target_ref]
                techniques[t_code]["procedure_count"] += 1

    return techniques

def determine_exclusion_threshold(techniques):
    """
    Analyzes procedure counts and determines a threshold.
    Returns:
        threshold: int
        excluded_techniques: list of T-codes
        included_techniques: list of T-codes
    """
    counts = [t["procedure_count"] for t in techniques.values()]
    if not counts:
        return 0, [], []

    # Calculate statistics
    avg = statistics.mean(counts)
    median = statistics.median(counts)
    try:
        p90 = statistics.quantiles(counts, n=10)[-1] # 90th percentile
    except AttributeError:
        # Fallback for older python versions if needed, though 3.12 has quantiles
        sorted_counts = sorted(counts)
        p90 = sorted_counts[int(len(sorted_counts) * 0.9)]

    # Heuristic: if p90 is very high, use it.
    # The user mentioned "too common to detect".
    # Let's use the 90th percentile as the cutoff.
    threshold = int(p90)

    excluded = []
    included = []

    for t_code, data in techniques.items():
        if data["procedure_count"] > threshold:
            excluded.append(t_code)
        else:
            included.append(t_code)

    print(f"Procedure Count Stats: Mean={avg:.2f}, Median={median}, 90th Percentile={threshold}")
    print(f"Threshold set to > {threshold} procedures.")

    return threshold, excluded, included

def load_trr_coverage(filepath):
    """
    Loads TRR index.json and extracts covered (technique_id, platform) pairs.
    Returns:
        covered_pairs: set of (T-code, Platform Name)
    """
    try:
        with open(filepath, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {filepath} not found.")
        sys.exit(1)

    # Map TRR specific platforms to ATT&CK platforms to ensure matches
    platform_mapping = {
        "Active Directory": ["Windows", "Identity Provider"],
        "Azure": ["IaaS", "Identity Provider", "SaaS", "Azure AD", "Office 365"], # Azure AD/O365 might be mapped to IdP/Office Suite in newer ATT&CK
        "Exchange Online": ["Office Suite", "SaaS", "Office 365"],
        "Windows": ["Windows"],
        "Linux": ["Linux"],
        "macOS": ["macOS"]
    }

    covered = set()
    for entry in data:
        t_codes = entry.get("external_ids", [])
        platforms = entry.get("platforms", [])
        for t in t_codes:
            for p in platforms:
                # Add the exact platform
                covered.add((t, p))
                # Add mapped platforms
                if p in platform_mapping:
                    for mapped_p in platform_mapping[p]:
                        covered.add((t, mapped_p))
    return covered

def generate_report(techniques, included_codes, excluded_codes, covered_pairs, threshold):
    """Generates the Markdown report."""

    # Explode included techniques into (T-code, Platform) pairs
    target_pairs = set()
    for t_code in included_codes:
        platforms = techniques[t_code]["platforms"]
        if not platforms:
             # Some techniques might not list platforms (rare, but possible).
             # Or they might be "PRE" platform which is distinct.
             # We skip if no platform is listed.
             pass
        for p in platforms:
            target_pairs.add((t_code, p))

    # Calculate Gaps
    # Gap = Target Pair not in Covered Pairs
    # Note: Platform names must match exactly.

    gaps = []
    covered_count = 0

    # We only care about gaps for included techniques
    for t_code, platform in target_pairs:
        if (t_code, platform) in covered_pairs:
            covered_count += 1
        else:
            gaps.append((t_code, platform))

    # Also check if we have coverage for things not in target (e.g. excluded techniques or different platforms)
    # But the requirement focuses on "Where are the gaps?"

    # Analysis by Tactic
    tactic_gaps = {} # Tactic -> count
    tactic_total = {} # Tactic -> total expected

    for t_code, platform in target_pairs:
        tactics = techniques[t_code]["tactics"]
        is_covered = (t_code, platform) in covered_pairs

        for tac in tactics:
            # Normalize tactic name (replace - with space and title case? ATT&CK uses 'persistence', 'defense-evasion' etc in phase_name)
            # phase_name is usually kebab-case (e.g. 'defense-evasion')
            # Let's make it Title Case for display
            tac_display = tac.replace('-', ' ').title()

            tactic_total[tac_display] = tactic_total.get(tac_display, 0) + 1
            if not is_covered:
                tactic_gaps[tac_display] = tactic_gaps.get(tac_display, 0) + 1

    # Analysis by Platform
    platform_gaps = {}
    platform_total = {}

    for t_code, platform in target_pairs:
        platform_total[platform] = platform_total.get(platform, 0) + 1
        if (t_code, platform) not in covered_pairs:
            platform_gaps[platform] = platform_gaps.get(platform, 0) + 1

    # Format the report
    with open(REPORT_PATH, 'w') as f:
        f.write("# TRR Coverage Analysis Report\n\n")

        f.write("## 1. Excluded Techniques (Too Common)\n")
        f.write(f"Techniques with > {threshold} procedures were excluded from the target list as they are likely too common/undetectable.\n\n")
        f.write("| Technique ID | Name | Procedure Count |\n")
        f.write("|---|---|---|\n")
        # Sort excluded by count descending
        excluded_sorted = sorted(excluded_codes, key=lambda x: techniques[x]["procedure_count"], reverse=True)
        for t_code in excluded_sorted:
            name = techniques[t_code]["name"]
            count = techniques[t_code]["procedure_count"]
            f.write(f"| {t_code} | {name} | {count} |\n")
        f.write("\n")

        f.write("## 2. Coverage Analysis\n\n")

        # Overall Stats
        total_targets = len(target_pairs)
        coverage_pct = (covered_count / total_targets * 100) if total_targets > 0 else 0
        f.write(f"**Overall Coverage:** {covered_count} / {total_targets} ({coverage_pct:.2f}%)\n\n")

        f.write("### Gaps by Tactic\n")
        f.write("| Tactic | Total Target Pairs | Gaps | Coverage %\n")
        f.write("|---|---|---|---|\n")
        # Sort by most gaps
        for tac in sorted(tactic_total.keys(), key=lambda x: tactic_gaps.get(x, 0), reverse=True):
            total = tactic_total[tac]
            gap = tactic_gaps.get(tac, 0)
            cov = total - gap
            pct = (cov / total * 100) if total > 0 else 0
            f.write(f"| {tac} | {total} | {gap} | {pct:.2f}% |\n")
        f.write("\n")

        f.write("### Platform Coverage (Least Covered First)\n")
        f.write("| Platform | Total Target Pairs | Gaps | Coverage %\n")
        f.write("|---|---|---|---|\n")
        # Sort by lowest coverage percentage
        platform_stats = []
        for plt in platform_total.keys():
            total = platform_total[plt]
            gap = platform_gaps.get(plt, 0)
            cov = total - gap
            pct = (cov / total * 100) if total > 0 else 0
            platform_stats.append((plt, total, gap, pct))

        platform_stats.sort(key=lambda x: x[3]) # Sort by pct ascending

        for plt, total, gap, pct in platform_stats:
            f.write(f"| {plt} | {total} | {gap} | {pct:.2f}% |\n")
        f.write("\n")

        f.write("## 3. Included Technique/Platform Pairs\n")
        f.write("List of techniques considered for coverage (Exploded by Platform).\n\n")
        f.write("| Technique ID | Platform | Covered? |\n")
        f.write("|---|---|---|\n")

        # Sort by Technique ID then Platform
        sorted_targets = sorted(list(target_pairs))
        for t_code, platform in sorted_targets:
            is_covered = "Yes" if (t_code, platform) in covered_pairs else "No"
            f.write(f"| {t_code} | {platform} | {is_covered} |\n")

    print(f"Report generated at {REPORT_PATH}")

def main():
    # 1. Fetch and Parse ATT&CK
    attack_data = fetch_attack_data()
    techniques = parse_attack_data(attack_data)

    # 2. Determine Exclusions
    threshold, excluded, included = determine_exclusion_threshold(techniques)

    # 3. Load TRR Coverage
    covered_pairs = load_trr_coverage(TRR_INDEX_PATH)

    # 4. Generate Report
    generate_report(techniques, included, excluded, covered_pairs, threshold)

if __name__ == "__main__":
    main()
