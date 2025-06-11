"""from datasets import load_dataset, Dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
import torch
import json

# Load dataset
with open("stride_synthetic_dataset_5000.json") as f:
    data = json.load(f)

labels = sorted(list(set(item["label"] for item in data)))
label2id = {l: i for i, l in enumerate(labels)}
id2label = {i: l for l, i in label2id.items()}

# Tokenizer & model
tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

def preprocess(example):
    return tokenizer(example["text"], truncation=True, padding="max_length", max_length=128)

# Dataset prep
dataset = Dataset.from_list([{"text": d["text"], "label": label2id[d["label"]]} for d in data])
dataset = dataset.train_test_split(test_size=0.2)
tokenized = dataset.map(preprocess, batched=True)

# Load model
model = AutoModelForSequenceClassification.from_pretrained("distilbert-base-uncased", num_labels=len(labels), id2label=id2label, label2id=label2id)

# Training config
args = TrainingArguments(
    output_dir="./stride-model",
    evaluation_strategy="epoch",
    logging_dir="./logs",
    learning_rate=2e-5,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    num_train_epochs=4,
    weight_decay=0.01,
    save_total_limit=1,
)

trainer = Trainer(
    model=model,
    args=args,
    train_dataset=tokenized["train"],
    eval_dataset=tokenized["test"],
    tokenizer=tokenizer,
)

trainer.train()
trainer.save_model("./stride-model")"""


"""from transformers import pipeline

classifier = pipeline("text-classification", model="./stride-model", tokenizer="distilbert-base-uncased")

risk = "A script modified system configurations, disabling endpoint protection."

prediction = classifier(risk)
print("Predicted STRIDE category:", prediction[0]["label"])"""


from sklearn.metrics import accuracy_score

from transformers import pipeline


classifier = pipeline("text-classification", model="./stride-model", tokenizer="distilbert-base-uncased")


unseen_risks = [
    "An attacker exploited a session ID in the URL to log in as another user.",  # Spoofing
    "A script modified system configurations, disabling endpoint protection.",  # Tampering
    "Employees were able to deny sending large files due to lack of file transfer logging.",  # Repudiation
    "The database backup was left unencrypted and downloaded from a public endpoint.",  # Info Disclosure
    "A flood of malformed HTTP requests overwhelmed the load balancer.",  # DoS
    "User credentials were captured using a fake login page.",  # Spoofing
    "Malicious code altered configuration files in the production server.",  # Tampering
    "Logs were not maintained, allowing users to deny performing critical actions.",  # Repudiation
    "Sensitive HR records were exposed through an open S3 bucket.",  # Info Disclosure
    "The system crashed when handling a high volume of connection requests.",  # DoS
    "Phishing email led users to an attacker-controlled portal.",  # Spoofing
    "Database schema was altered without proper authorization.",  # Tampering
    "Transactions lacked non-repudiation measures, causing audit gaps.",  # Repudiation
    "Medical reports were accessed without patient consent.",  # Info Disclosure
    "Botnet traffic caused service unavailability across nodes.",  # DoS
    "Fake tokens were used to impersonate a valid identity.",  # Spoofing
    "Software updates were tampered with to introduce backdoors.",  # Tampering
    "No audit trail existed for deleted financial records.",  # Repudiation
    "Financial statements were leaked via an insecure API endpoint.",  # Info Disclosure
    "Repeated API requests overwhelmed the server capacity."  # DoS
]

true_labels = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service"
]

predicted_labels = []
for risk in unseen_risks:
    prediction = classifier(risk)
    predicted_labels.append(prediction[0]['label'])


accuracy = accuracy_score(true_labels, predicted_labels) * 100
print(f"Model Accuracy: {accuracy:.2f}%")


