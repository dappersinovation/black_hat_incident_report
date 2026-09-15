import re

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# Keyword -> triage mapping. Order matters: the first matching rule wins.
SEVERITY_RULES = [
    {
        "keywords": ("locked", "ransomware", "encrypted"),
        "severity": "Critical",
        "department": "Incident Response Team",
        "mitre": "T1486 (Data Encrypted for Impact)",
        "act_section": "Section 14 (System Interference & Sabotage)",
        "legal_description": "Unlawful modification/deletion of critical data and ransomware extortion.",
    },
    {
        "keywords": ("payroll", "nin", "staff id", "password"),
        "severity": "Critical",
        "department": "Identity & Access Management",
        "mitre": "T1110 (Brute Force)",
        "act_section": "Section 13 (Unlawful Access to Computer Data)",
        "legal_description": "Unauthorized penetration of protected financial/identity databases.",
    },
    {
        "keywords": ("man-in-the-middle", "man in the middle", "mitm", "rogue wifi",
                     "fake hotspot", "arp spoofing", "intercepted our traffic"),
        "severity": "Critical",
        "department": "Network Security Team",
        "mitre": "T1557 (Adversary-in-the-Middle)",
        "act_section": "Section 12 (Unlawful Interception of Electronic Communication)",
        "legal_description": "Unauthorized interception of non-public electronic communication or data in transit between two computer systems.",
    },
    {
        "keywords": ("firewall", "bypassed the firewall", "perimeter defense",
                     "port scan", "unauthorized port", "disabled our firewall"),
        "severity": "Critical",
        "department": "Network Security Team",
        "mitre": "T1599 (Network Boundary Bridging)",
        "act_section": "Section 6 (Unlawful Access to a Computer) & Section 5 (Offences Against Critical National Information Infrastructure)",
        "legal_description": "Circumvention of network perimeter security controls to gain unauthorized entry into a protected computer system.",
    },
    {
        "keywords": ("pivot", "pivoted", "lateral movement", "jumped to another server",
                     "moved to the internal server", "compromised another server"),
        "severity": "Critical",
        "department": "Incident Response Team",
        "mitre": "T1021 (Remote Services) / T1090 (Proxy)",
        "act_section": "Section 6 (Unlawful Access to a Computer) read with Section 9 (System Interference)",
        "legal_description": "Using a compromised host as a foothold to gain unauthorized access to additional systems on the network.",
    },
    {
        "keywords": ("link", "grant", "scholarship", "whatsapp"),
        "severity": "High",
        "department": "IT Security Team",
        "mitre": "T1566 (Phishing)",
        "act_section": "Section 32 (Phishing & Computer-Related Fraud)",
        "legal_description": "Creation of fraudulent electronic communications to harvest credentials.",
    },
    {
        "keywords": ("xss", "cross-site scripting", "script injection",
                     "<script>", "injected a malicious script"),
        "severity": "High",
        "department": "Application Security Team",
        "mitre": "CAPEC-63 (Cross-Site Scripting)",
        "act_section": "Section 8 (Unauthorized Modification of Computer Programs or Data)",
        "legal_description": "Injection of unauthorized script code into a web application to alter its behaviour or compromise its visitors.",
    },
    {
        "keywords": ("prompt injection", "jailbreak", "jailbroke", "poisoned the model",
                     "poisoned our ai", "adversarial input", "manipulated the chatbot",
                     "manipulated the ai model"),
        "severity": "High",
        "department": "AI/ML Security Team",
        "mitre": "MITRE ATLAS AML.T0051 (LLM Prompt Injection)",
        "act_section": "Section 8 (Unauthorized Modification of Computer Programs or Data) — persuasive analogy; no dedicated AI-attack provision exists yet",
        "legal_description": (
            "Manipulation of an AI/ML system's inputs, training data, or instructions to bypass "
            "controls or extract unauthorized behaviour. Nigeria's Cybercrimes Act (2015, as amended "
            "2024) has no AI-specific offence; this is triaged under general system-interference "
            "provisions pending dedicated AI legislation (see NDPA 2023 and NITDA's National AI Strategy)."
        ),
    },
    {
        "keywords": ("defacement", "hacked by", "landing page"),
        "severity": "Medium",
        "department": "Web Operations Team",
        "mitre": "T1491 (Defacement)",
        "act_section": "Section 18 (Tampering with Critical Infrastructure)",
        "legal_description": "Unauthorized defacement or alteration of public web properties.",
    },
]

DEFAULT_TRIAGE = {
    "severity": "Low",
    "department": "General IT Desk",
    "mitre": "T1000 (Unclassified)",
    "act_section": "General Administrative Violation",
    "legal_description": "Unclassified operational incident requiring standard review.",
}

PII_PATTERNS = (
    (re.compile(r'[\w\.-]+@[\w\.-]+\.\w+'), '[REDACTED_EMAIL]'),
    (re.compile(r'(\+234|0)[789][01]\d{8}'), '[REDACTED_PHONE]'),
    (re.compile(r'\b\d{11}\b'), '[REDACTED_NIN]'),
    (re.compile(r'\bSTF-\d{4}\b'), '[REDACTED_STAFF_ID]'),
)

DUPLICATE_THRESHOLD = 0.60

CRITICAL_RULE_COUNT = sum(1 for rule in SEVERITY_RULES if rule["severity"] == "Critical")


class IncidentPipeline:
    """Classifies incident reports, redacts PII, and flags likely duplicates."""

    def __init__(self):
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(ngram_range=(1, 2))),
            ('clf', MultinomialNB())
        ])
        self.dedup_vectorizer = TfidfVectorizer()
        self.indexed_reports = []
        self.indexed_vectors = None

    def redact_pii(self, text: str) -> str:
        """Strip emails, phone numbers, NINs and staff IDs from raw text."""
        for pattern, replacement in PII_PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def train(self, df: pd.DataFrame):
        """Fit the classifier and index the (redacted) corpus for similarity lookups."""
        self.model.fit(df['raw_text'], df['ground_truth_category'])
        self.indexed_reports = [self.redact_pii(t) for t in df['raw_text']]
        self.indexed_vectors = self.dedup_vectorizer.fit_transform(self.indexed_reports)

    def evaluate(self, df: pd.DataFrame):
        """Return accuracy and a full classification report against ground truth."""
        preds = self.model.predict(df['raw_text'])
        acc = accuracy_score(df['ground_truth_category'], preds)
        report = classification_report(df['ground_truth_category'], preds, output_dict=True)
        return acc, report

    def _find_duplicate(self, clean_text: str):
        vec = self.dedup_vectorizer.transform([clean_text])
        similarities = cosine_similarity(vec, self.indexed_vectors)[0]
        idx = similarities.argmax()
        score = similarities[idx]
        is_duplicate = bool(score > DUPLICATE_THRESHOLD)
        cluster_id = f"CLUSTER-00{idx % 4 + 1}" if is_duplicate else "NEW-INCIDENT"
        return is_duplicate, round(float(score) * 100, 1), cluster_id

    def _classify_severity(self, text_lower: str) -> dict:
        for rule in SEVERITY_RULES:
            if any(kw in text_lower for kw in rule["keywords"]):
                return rule
        return DEFAULT_TRIAGE

    def process_report(self, raw_report: str) -> dict:
        """Run the full triage flow on one incident: redact, classify, dedupe, map to law."""
        clean_text = self.redact_pii(raw_report)
        predicted_category = self.model.predict([clean_text])[0]
        is_duplicate, match_confidence, cluster_id = self._find_duplicate(clean_text)
        triage = self._classify_severity(clean_text.lower())

        return {
            "clean_text": clean_text,
            "category": predicted_category,
            "severity": triage["severity"],
            "department": triage["department"],
            "mitre": triage["mitre"],
            "cyber_act_section": triage["act_section"],
            "legal_description": triage["legal_description"],
            "is_duplicate": is_duplicate,
            "match_confidence": match_confidence,
            "cluster_id": cluster_id,
        }
