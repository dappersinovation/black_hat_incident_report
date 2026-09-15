import random

import pandas as pd

INCIDENT_TEMPLATES = [
    {
        "template": "Good morning sir, someone sent this link on our department WhatsApp group claiming the VC is giving 50k grant: {link}. My email is {email} and my phone is {phone}.",
        "category": "Phishing / Social Engineering",
        "cluster": "CLUSTER-001",
    },
    {
        "template": "Abeg check this link {link}. Dey say make I put my portal password to claim laptop scholarship. My phone number na {phone}.",
        "category": "Phishing / Social Engineering",
        "cluster": "CLUSTER-001",
    },
    {
        "template": "Hello admin, I tried logging into the payroll portal and it asked for my password twice. Now my account is locked. Staff ID: {staff_id}, NIN: {nin}.",
        "category": "Credential Compromise",
        "cluster": "CLUSTER-002",
    },
    {
        "template": "Sir, the school public library landing page is showing a strange message saying 'Hacked by X-Ghost'. Link: {link}. Contact me on {phone}.",
        "category": "Web Defacement",
        "cluster": "CLUSTER-003",
    },
    {
        "template": "All the files in the finance folder now have .locked extension and there is a readme.txt asking for money. Help fast! Phone: {phone}.",
        "category": "Ransomware / Malware",
        "cluster": "CLUSTER-004",
    },
    {
        "template": "Sir, IT flagged that someone set up a rogue wifi hotspot in the cafeteria and intercepted our traffic — looks like a man-in-the-middle attack on staff logins. Reach me on {phone}.",
        "category": "Man-in-the-Middle (MITM) Attack",
        "cluster": "CLUSTER-005",
    },
    {
        "template": "Our web team found an XSS script injection on the student portal comment box, someone injected a malicious script tag to steal session cookies. Contact: {email}.",
        "category": "Web Application Attack (XSS)",
        "cluster": "CLUSTER-006",
    },
    {
        "template": "Security noticed a port scan and then the perimeter firewall was bypassed overnight, attacker got into the DMZ server. My phone is {phone}.",
        "category": "Firewall Breach / Perimeter Bypass",
        "cluster": "CLUSTER-007",
    },
    {
        "template": "After the initial breach the attacker pivoted from the web server and moved laterally to the internal database server. Escalating to IR now, call {phone}.",
        "category": "Lateral Movement / Server Pivoting",
        "cluster": "CLUSTER-008",
    },
    {
        "template": "Someone used a prompt injection to jailbreak our support chatbot and got it to leak internal staff data. Staff ID {staff_id}, please investigate.",
        "category": "AI System Attack (Prompt Injection / Model Abuse)",
        "cluster": "CLUSTER-009",
    },
]

# Reference coordinates for a handful of Nigerian cities; used to scatter
# synthetic reports across a map.
NIGERIA_LOCATIONS = [
    {"city": "Lagos", "lat": 6.5244, "lon": 3.3792},
    {"city": "Abuja", "lat": 9.0765, "lon": 7.3986},
    {"city": "Nasarawa", "lat": 8.4931, "lon": 8.5153},
    {"city": "Kano", "lat": 12.0022, "lon": 8.5920},
    {"city": "Port Harcourt", "lat": 4.8156, "lon": 7.0498},
    {"city": "Enugu", "lat": 6.4584, "lon": 7.5464},
]

DOMAINS = [
    "http://fulafia-grant-portal.free.site",
    "http://update-payroll-verify.ng",
    "http://scholarship-tech.tk",
]
EMAILS = ["john.doe@fulafia.edu.ng", "m.ibrahim@yahoo.com", "blessing.a@gmail.com"]
PHONES = ["08031234567", "07089876543", "08123456789"]
STAFF_IDS = ["STF-8821", "STF-3301", "STF-1049"]
NINS = ["12345678901", "98765432109", "45678912301"]

COORD_JITTER = 0.15
REPORT_COUNT = 300
OUTPUT_PATH = "synthetic_incidents.csv"


def generate_dataset(count: int = REPORT_COUNT) -> pd.DataFrame:
    rows = []
    for i in range(count):
        template = random.choice(INCIDENT_TEMPLATES)
        location = random.choice(NIGERIA_LOCATIONS)

        text = template["template"].format(
            link=random.choice(DOMAINS),
            email=random.choice(EMAILS),
            phone=random.choice(PHONES),
            staff_id=random.choice(STAFF_IDS),
            nin=random.choice(NINS),
        )

        rows.append({
            "report_id": f"REP-{i + 1001}",
            "raw_text": text,
            "ground_truth_category": template["category"],
            "true_cluster_id": template["cluster"],
            "city": location["city"],
            "lat": location["lat"] + random.uniform(-COORD_JITTER, COORD_JITTER),
            "lon": location["lon"] + random.uniform(-COORD_JITTER, COORD_JITTER),
        })

    return pd.DataFrame(rows)


if __name__ == "__main__":
    df = generate_dataset()
    df.to_csv(OUTPUT_PATH, index=False)
    print(f"Generated {len(df)} synthetic incidents -> {OUTPUT_PATH}")
