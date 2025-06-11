import json
from sentence_transformers import SentenceTransformer, util
import torch


with open("mitre_techniques_only.json") as f:
    all_techniques = json.load(f)


technique_texts = []
for t in all_techniques:
    name = t.get("name", "")
    desc = t.get("description", "")
    full_text = f"{name}. {desc}"
    technique_texts.append(full_text)


model = SentenceTransformer("all-MiniLM-L6-v2")


technique_embeddings = model.encode(technique_texts, convert_to_tensor=True)


def map_to_mitre_techniques(threat_text, top_k=3):
    query_embedding = model.encode(threat_text, convert_to_tensor=True)
    cos_scores = util.cos_sim(query_embedding, technique_embeddings)[0]
    top_results = torch.topk(cos_scores, k=top_k)

    results = []
    for score, idx in zip(top_results.values, top_results.indices):
        tech = all_techniques[idx]
        results.append({
            "technique_name": tech.get("name", "N/A"),
            "technique_id": tech.get("external_references", [{}])[0].get("external_id", "N/A"),
            "description": tech.get("description", "No description"),
            "tactics": [p["phase_name"] for p in tech.get("kill_chain_phases", [])],
            "platforms": tech.get("x_mitre_platforms", []),
            "url": tech.get("external_references", [{}])[0].get("url", "#"),
            "score": float(score)
        })
    return results




print(map_to_mitre_techniques("Adversary dumped LSASS process to extract credentials."))