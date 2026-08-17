import json
from pathlib import Path

from src.schemas import ReconItem, ReconResult
from src.tools import questions, send_query


def recon_node(state: dict) -> dict:
    print("[+] Starting Reconnaissance...")

    items = []
    for i, query in enumerate(questions, 1):
        try:
            response = send_query(query)
        except Exception as exc:  # noqa: BLE001
            print(f"    Query {i} failed permanently: {exc}")
            response = f"[ERROR: {exc}]"
        items.append(ReconItem(query=query, response=response))

    recon = ReconResult(items=items)

    path = Path("reports") / "recon" / f"{state['session_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(recon.model_dump(), indent=2, ensure_ascii=False))

    print("[+] Reconnaissance complete")

    return {"recon_data": recon}