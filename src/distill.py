"""Build a fine-tuning dataset from attacker LLM traces.

Each example is a full conversation the attacker LLM had:
  system    – the red-team attacker persona
  user      – class description + tactics + previous attempt history + feedback
  assistant – the adversarial prompt the attacker LLM generated

Appends to reports/distilled_dataset.jsonl locally.
If LANGSMITH_API_KEY is set, also pulls runs from the LangSmith project and
converts them into a named dataset, excluding target model traces.
"""

import json
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

OUTPUT_FILE = Path("reports/distilled_dataset.jsonl")
LANGSMITH_DATASET = "Attacker Traces Dataset"
TARGET_MODEL = os.getenv("TARGET_MODEL", "")
PROJECT_NAME = os.getenv("LANGSMITH_PROJECT")


def push_to_langsmith(traces: list[dict]) -> None:
    from langsmith import Client

    client = Client()

    # Get or create dataset
    existing = {d.name for d in client.list_datasets()}
    if LANGSMITH_DATASET in existing:
        dataset = next(d for d in client.list_datasets() if d.name == LANGSMITH_DATASET)
    else:
        dataset = client.create_dataset(
            LANGSMITH_DATASET,
            description="Attacker LLM traces converted from project runs.",
        )

    # Pull runs from project, skip target model traces
    print(f"[distill] fetching runs from project '{PROJECT_NAME}'...")
    runs = client.list_runs(project_name=PROJECT_NAME, is_root=True, error=False)

    examples = []
    skipped = 0
    for run in runs:
        model = (run.extra or {}).get("metadata", {}).get("model", "")
        if TARGET_MODEL and model == TARGET_MODEL:
            skipped += 1
            continue
        examples.append({
            "inputs": run.inputs,
            "outputs": run.outputs or {},
        })

    # Also include the current session's attacker traces
    for trace in traces:
        messages = trace["messages"]
        examples.append({
            "inputs": {"messages": messages[:-1]},
            "outputs": {"message": messages[-1]},
        })

    if examples:
        client.create_examples(dataset_id=dataset.id, examples=examples)

    print(f"[distill] pushed {len(examples)} examples to '{LANGSMITH_DATASET}' ({skipped} target traces skipped)")


def distill_node(state: dict) -> dict:
    traces = state.get("attacker_traces", [])

    if not traces:
        return {"distill_count": 0}

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_FILE.open("a") as f:
        for trace in traces:
            f.write(json.dumps(trace, ensure_ascii=False) + "\n")

    if os.getenv("LANGSMITH_API_KEY"):
        push_to_langsmith(traces)

    return {"distill_count": len(traces)}
