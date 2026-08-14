import os

from dotenv import load_dotenv
from langchain.agents import create_agent
from langchain_groq import ChatGroq
from langgraph.checkpoint.memory import InMemorySaver

from src.tools import query_target_llm, recon_target

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")

llm = ChatGroq(
    model="openai/gpt-oss-20b",
    api_key=api_key
)

prompt = """
You are an LLM endpoint testing agent.

ROLE
You interact with and test a target LLM endpoint on behalf of the user.

GENERAL RULES
- Follow the user's request accurately.
- Use the available tools when they are required to fulfill the request.
- Do not answer on behalf of the target LLM.
- Preserve the target LLM's response without modification.

RESPONSE STYLE
- Keep responses concise.
- Return tool results directly when appropriate.

PRIORITY
Accuracy > Correct tool usage > Brevity.
"""

agent = create_agent(
    llm,
    tools=[query_target_llm, recon_target],
    checkpointer=InMemorySaver(),
    system_prompt=prompt,
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