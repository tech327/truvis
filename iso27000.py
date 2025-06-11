from sentence_transformers import SentenceTransformer, util
import json


with open("iso_27001_2022_controls.json") as f:
    iso_data = json.load(f)


iso_controls = []
for section in iso_data:
    for ctrl in section["controls"]:
        iso_controls.append({
            "id": ctrl["id"],
            "title": ctrl["title"],
            "section": section["section"]
        })


model = SentenceTransformer('all-MiniLM-L6-v2')


iso_embeddings = model.encode([c["title"] for c in iso_controls], convert_to_tensor=True)

def map_to_iso_controls(threat_text, top_k=3):
    query_embedding = model.encode(threat_text, convert_to_tensor=True)
    cos_scores = util.cos_sim(query_embedding, iso_embeddings)[0]
    top_results = cos_scores.topk(k=top_k)

    results = []
    for score, idx in zip(top_results.values, top_results.indices):
        ctrl = iso_controls[idx]
        results.append({
            "iso_control_id": ctrl["id"],
            "iso_control_title": ctrl["title"],
            "section": ctrl["section"],
            "score": float(score)
        })
    return results

if __name__ == "__main__":
    result = map_to_iso_controls("An admin deleted several logs, and now actions cannot be traced to any user.")
    print(result)

