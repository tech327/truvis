import fitz  # PyMuPDF
import json
import re
import string
from rapidfuzz import fuzz


def load_mitre(file_path="enterprise-attack.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return [obj for obj in data["objects"] if obj.get("type") == "attack-pattern"]

# === STRIDE Classifier ===
with open("stride_5000_techniques.json", "r") as f:
    stride_keywords = json.load(f)

def stride_classify(text):
    text = text.lower()

    for category, keywords in stride_keywords.items():
        if any(term.lower() in text for term in keywords):
            return category

    return "Uncategorized"


# === MITRE Technique Matcher ===
def search_mitre(text, techniques):
    text = text.lower()
    words = [w for w in re.findall(r"\b\w+\b", text) if len(w) > 4]
    results = []
    for tech in techniques:
        name = tech.get("name", "").lower()
        desc = tech.get("description", "").lower()
        for word in words:
            if word in name or word in desc:
                results.append({
                    "id": tech.get("external_references", [{}])[0].get("external_id", "N/A"),
                    "name": tech.get("name", ""),
                    "url": tech.get("external_references", [{}])[0].get("url", "#")
                })
                break
    return results[:2]

# === Load ISO Controls with Keywords
def load_iso_controls_with_keywords(file_path="iso_27001_2022_controls.json"):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    flat_controls = []
    stopwords = {"the", "of", "and", "or", "to", "in", "for", "use", "with", "on", "by", "a", "an", "at"}

    for section in data:
        for ctrl in section.get("controls", []):
            words = ctrl["title"].lower().translate(str.maketrans('', '', string.punctuation)).split()
            keywords = [word for word in words if word not in stopwords and len(word) > 3]
            flat_controls.append({
                "id": ctrl["id"],
                "title": ctrl["title"],
                "keywords": keywords,
                "fulltext": f"{ctrl['id']} {ctrl['title']}".lower()
            })
    return flat_controls

# === ISO 27001 Matcher (Hybrid: Fuzzy + Keywords)
def match_iso_controls_hybrid(text, controls, threshold=55):
    text_lower = text.lower()
    matches = []

    # Fuzzy match
    for ctrl in controls:
        score = fuzz.partial_ratio(text_lower, ctrl["fulltext"])
        if score >= threshold:
            matches.append((score, f"{ctrl['id']} - {ctrl['title']}"))

    # Keyword match
    keyword_hits = []
    for ctrl in controls:
        for kw in ctrl["keywords"]:
            if kw in text_lower:
                keyword_hits.append(f"{ctrl['id']} - {ctrl['title']}")
                break

    fuzzy_results = [m[1] for m in sorted(matches, reverse=True)]
    combined = list(dict.fromkeys(fuzzy_results + keyword_hits))[:3]
    return combined

# === Extract Text from PDF
def extract_text_from_pdf(pdf_path):
    doc = fitz.open(pdf_path)
    return "\n".join(page.get_text() for page in doc)

# === Full Analysis Pipeline
def process_pdf(pdf_path, mitre_json="enterprise-attack.json", iso_json="iso_27001_2022_controls.json"):
    print(f"Processing {pdf_path}...")
    full_text = extract_text_from_pdf(pdf_path)
    mitre_techniques = load_mitre(mitre_json)
    iso_controls = load_iso_controls_with_keywords(iso_json)

    seen_risks = set()
    results = []
    lines = full_text.split("\n")
    for line in lines:
        line = re.sub(r"^\d+[\.\)]\s*", "", line).strip()
        if not line or len(line) < 10:
            continue
        if (
            "routine log line" in line.lower()
            or "no notable activity recorded" in line.lower()
        ):
            continue
        if line.lower() in seen_risks:
            continue
        seen_risks.add(line.lower())

        stride = stride_classify(line)
        mitre_hits = search_mitre(line, mitre_techniques)
        iso_hits = match_iso_controls_hybrid(line, iso_controls)
        results.append({
            "risk_text": line,
            "stride_category": stride,
            "mitre_matches": mitre_hits,
            "iso_controls": iso_hits
        })

    return results

# === Run Script
if __name__ == "__main__":
    results = process_pdf("sample_risk_report_200_lines.pdf")
    for item in results:
        print("\n Risk:", item['risk_text'])
        print("    STRIDE:", item['stride_category'])
        print("    MITRE Techniques:")
        if item['mitre_matches']:
            for m in item['mitre_matches']:
                print(f"     - {m['name']} ({m['id']}) → {m['url']}")
        else:
            print("     - None")
        print("    ISO 27001 Controls:")
        if item['iso_controls']:
            for ctrl in item['iso_controls']:
                print(f"     - {ctrl}")
        else:
            print("     - None")
