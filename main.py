import os

import requests
from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain.tools import tool
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.checkpoint.memory import InMemorySaver

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

llm = ChatGoogleGenerativeAI(
    model="gemini-3.6-flash",
    google_api_key=api_key
)

target = "http://localhost:7002/v1/chat/completions"

@tool
def query_target_llm(query: str) -> str:
    """Send a query to the target LLM endpoint and return its response."""

    response = requests.post(
        target,
        headers={"Content-Type": "application/json"},
        json={
            "messages": [
                {
                    "role": "user",
                    "content": query
                }
            ]
        },
        timeout=60
    )

    response.raise_for_status()

    data = response.json()

    return data["choices"][0]["message"]["content"]

prompt = """
You are an LLM endpoint testing agent.
Send every user query exactly as provided to the target LLM using the query_target_llm tool.
Return the target LLM's response without modifying it.
"""

agent = create_agent(
    llm,
    tools=[query_target_llm],
    checkpointer=InMemorySaver(),
    system_prompt = prompt,
    )


print("Hello. Hope you had a good day. Type 'exit' or 'quit' to end the conversation.")

while True:
    query = input("You: ")
    if query.strip().lower() in ["exit", "quit"]:
        print("Goodbye!")
        break
    response = agent.invoke(
        {"messages": [{"role": "user", "content": query}]},
        config={"configurable": {"thread_id": "1"}}
    )
    text = response["messages"][-1].text
    print("Agent:", text)