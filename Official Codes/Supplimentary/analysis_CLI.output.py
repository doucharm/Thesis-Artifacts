import json
import glob
from collections import defaultdict
import os

def analyze_trivy_reports(directory_path="."):
    package_data = defaultdict(lambda: {"total_occurrences": 0, "cves": {}})
    files = glob.glob(os.path.join(directory_path, "*.json"))
    
    if not files:
        print("No JSON files found in the specified directory.")
        return

    print(f"Found {len(files)} report(s). Analyzing...\n")
    print("=" * 70)
    
    for file in files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                for result in data.get('Results', []):
                    # STRICT FILTERING: Ignore misconfigs, secrets, and licenses
                    result_class = result.get('Class', '')
                    if result_class in ['config', 'secret', 'license']:
                        continue 
                        
                    # Only process the Vulnerabilities array
                    for vuln in result.get('Vulnerabilities', []):
                        pkg_name = vuln.get('PkgName', 'Unknown Library')
                        cve_id = vuln.get('VulnerabilityID', 'Unknown CVE')
                        fixed_version = vuln.get('FixedVersion')
                        status = vuln.get('Status', 'unknown')
                        
                        package_data[pkg_name]["total_occurrences"] += 1
                        
                        if cve_id not in package_data[pkg_name]["cves"]:
                            has_patch = bool(fixed_version)
                            package_data[pkg_name]["cves"][cve_id] = {
                                "has_patch": has_patch,
                                "fixed_version": fixed_version,
                                "status": status
                            }
        except Exception as e:
            print(f"Error reading {file}: {e}")

    # Sort libraries by the number of unique CVEs (highest first)
    sorted_pkgs = sorted(
        package_data.items(), 
        key=lambda x: len(x[1]["cves"]), 
        reverse=True
    )

    # Print the grouped analysis
    for pkg, data in sorted_pkgs:
        total = data["total_occurrences"]
        unique_cves = len(data["cves"])
        
        print(f"📦 Library: {pkg}")
        print(f"   Total Occurrences (across all images): {total}")
        print(f"   Unique Vulnerabilities:                {unique_cves}")
        print(f"   Vulnerability Details:")
        
        for cve, patch_info in data["cves"].items():
            if patch_info["has_patch"]:
                patch_str = f"✅ Patch Available (Fixed in: {patch_info['fixed_version']})"
            else:
                status_text = f"Status: {patch_info['status']}" if patch_info['status'] != 'unknown' else "No fixed version listed"
                patch_str = f"❌ No Patch ({status_text})"
                
            print(f"      - {cve:<18} {patch_str}")
        print("-" * 70)

if __name__ == "__main__":
    analyze_trivy_reports(".")