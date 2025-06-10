from attackcti import attack_client

def load_mitre_attack_data():
    lift = attack_client()
    enterprise = lift.get_enterprise()
    return enterprise['techniques']

def search_techniques(keyword, techniques):
    results = []
    keyword_lower = keyword.lower()
    for technique in techniques:
        if keyword_lower in technique.get('name', '').lower() or keyword_lower in technique.get('description', '').lower():
            results.append({
                "name": technique.get("name"),
                "id": technique.get("external_references", [{}])[0].get("external_id", "N/A"),
                "description": technique.get("description", "No description"),
                "tactics": technique.get("kill_chain_phases", []),
                "platforms": technique.get("x_mitre_platforms", []),
                "url": technique.get("external_references", [{}])[0].get("url", "#")
            })
    return results

# 🔍 Example usage:
if __name__ == "__main__":
    print("Loading MITRE ATT&CK techniques...")
    techniques = load_mitre_attack_data()

    keyword = input("Enter a keyword to search (e.g., phishing, credential): ")
    matches = search_techniques(keyword, techniques)

    if matches:
        print(f"\nFound {len(matches)} matching techniques:\n")
        for match in matches:
            print(f"🔹 {match['name']} ({match['id']})")
            print(f"   ↪ Description: {match['description'][:150]}...")
            print(f"   ↪ Tactics: {[t['phase_name'] for t in match['tactics']]}")
            print(f"   ↪ Platforms: {match['platforms']}")
            print(f"   ↪ URL: {match['url']}\n")
    else:
        print("No matching techniques found.")