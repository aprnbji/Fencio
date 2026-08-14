from typing import TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph

from src.analyze import analyze_node
from src.recon import recon_node
from src.schemas import ReconResult, VulnerabilityReport


class State(TypedDict, total=False):
    session_id: str
    recon_data: ReconResult
    analysis: VulnerabilityReport


graph = StateGraph(State)
graph.add_node("recon", recon_node)
graph.add_node("analyze", analyze_node)
graph.add_edge(START, "recon")
graph.add_edge("recon", "analyze")
graph.add_edge("analyze", END)
app = graph.compile()

if __name__ == "__main__":
    print("[graph] starting run")
    result = app.invoke({"session_id": str(uuid4())})
    print("[graph] finished")
    print(result["analysis"].model_dump_json(indent=2))