# Autonomous Red Teaming Agent

https://github.com/user-attachments/assets/d028ccec-501f-450c-9abe-2b218276fdf7

An autonomous security assessment framework built with LangGraph to test AI agents for vulnerabilities including prompt injections, system prompt extraction, indirect prompt injections, tool abuse, and credential leaks.

It uses an adaptive offensive LLM loop to execute iterative attack strategies, analyze target behaviors, and generate structured vulnerability reports.

## Features


- Reconnaissance : Sends diagnostic queries to map target capabilities and baseline behavior.
- Attack Surface Analysis : Analyzes recon logs to identify vulnerable entry points and structural attack surfaces.
- Adaptive Attack Loop : Uses an attack dictionary with diverse tactics to test vulnerabilities. If an attack fails, the Strategist adapts the payload using judge feedback until it passes the threshold or hits the attempt cap; upon success, it records the finding and moves to the next category.
- Knowledge Distillation : Captures successful attacker traces and exports datasets for model distillation.
- Reporting: Generates a final security report of all confirmed exploits.  

## Architecture
<img width="3360" height="1322" alt="Untitled" src="https://github.com/user-attachments/assets/470bf532-dfde-4bd9-a3d5-cbdc3b7549fa" />

10 attack categories are evaluated
- Prompt Injection: Overriding instructions via authority claims, roleplay, or delimiters.
- System Prompt Extraction: Leaking internal configuration using extraction framing.
- Indirect Prompt Injection: Executing attacker instructions embedded in external content.
- Sensitive Information Disclosure: Extracting secrets, API keys, and credentials.
- Tool Abuse / Excessive Agency: Executing unauthorized shell commands or file access.
- MCP Tool Exploitation: Path traversal, SSRF, or command injection via tool arguments.
- Tool Registry Poisoning: Convincing the target to register unverified external tools.
- Supply Chain Compromise: Inducing installation of compromised dependencies or skills.
- Tool MITM: Intercepting traffic via proxy redirection or disabling TLS verification.
- Agent-to-Agent Trust Abuse: Identity spoofing and forged delegation between agents.

## Project Structure

```text
.
├── .env
├── main.py
├── reports/
│   ├── attack/
│   │   ├── assessments/
│   │   ├── attack_results/
│   │   ├── findings/
│   ├── recon/
│   ├── vuln_analysis/
├── requirements.txt
└── src
    ├── analyze.py
    ├── attack.py
    ├── distill.py
    ├── recon.py
    ├── schemas.py
    ├── tests.py
    └── tools.py

```

## Set Up

Clone the repository:

```
git clone https://github.com/aprnbji/Fencio.git
cd Fencio
```

Install dependencies:

```
pip install -r requirements.txt
```

Create your .env file

```
GROq_API_KEY=

LANGSMITH_TRACING=true
LANGSMITH_API_KEY=
LANGSMITH_PROJECT=Fencio

TARGET_URL=
DVAA_URL=http://localhost:9000
```

Usage

```
python3 main.py
```

Generated results are organised under:

```text
reports/
├── attack/
├── recon/
└── vuln_analysis/
```


