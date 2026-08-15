import json
from pathlib import Path

from src.tools import questions, send_query
from src.schemas import ReconItem, ReconResult


def recon_node(state: dict) -> dict:
    print("[recon] starting recon sweep...")

    items = []
    for i, query in enumerate(questions, 1):
        print(f"[recon] question {i}/{len(questions)}...")
        try:
            response = send_query(query)
        except Exception as exc:
            print(f"[recon] question {i} failed permanently: {exc}")
            response = f"[ERROR: {exc}]"
        items.append(ReconItem(query=query, response=response))

    recon = ReconResult(items=items)

    print("[recon] done")

    path = Path("reports") / "recon" / f"{state['session_id']}.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            recon.model_dump(),
            indent=2,
            ensure_ascii=False,
        )
    )

    print(f"[recon] saved to {path}")

    return {
        "recon_data": recon
    }