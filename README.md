# Autonomous Red Teaming Agent

An autonomous security assessment framework built with LangGraph to test AI agents for vulnerabilities including prompt injections, system prompt extraction, indirect prompt injections, tool abuse, and credential leaks.

The system uses an adaptive offensive LLM loop to execute iterative attack strategies, analyze target behaviors, and generate structured vulnerability reports.


## Architecture
<img width="1612" height="595" alt="image" src="https://github.com/user-attachments/assets/8d654f3f-41db-437b-a949-907804ef61d2" />

- Reconnaissance : Sends diagnostic queries to map target capabilities and baseline behavior.
- Attack Surface Analysis : Analyzes recon logs to identify vulnerable entry points and structural attack surfaces.
- Adaptive Attack Loop : Uses an attack dictionary with diverse tactics to test vulnerabilities. If an attack fails, the Strategist adapts the payload using judge feedback until it passes the threshold or hits the attempt cap; upon success, it records the finding and moves to the next category.
- Knowledge Distillation : Captures successful attacker traces and exports datasets for model distillation.
- Reporting: Generates a final security report of all confirmed exploits.  
