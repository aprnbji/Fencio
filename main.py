import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.agents import create_agent
from langgraph.checkpoint.memory import InMemorySaver

load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

llm = ChatGoogleGenerativeAI(
    model="gemini-3.6-flash",
    google_api_key=api_key
)

agent = create_agent(
    llm,
    tools=[],
    checkpointer=InMemorySaver()
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