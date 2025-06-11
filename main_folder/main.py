import json

with open("enterprise-attack.json") as f:
    data = json.load(f)

# Filter only attack-pattern entries
techniques = [obj for obj in data["objects"] if obj["type"] == "attack-pattern"]

# Save to smaller file
with open("mitre_techniques_only.json", "w") as f_out:
    json.dump(techniques, f_out, indent=2)

print(f"Saved {len(techniques)} techniques.")