import langchain

from langchain.agents import Tool
from langchain.agents import AgentType
from langchain.chat_models import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain import OpenAI, LLMMathChain
from langchain.utilities import SerpAPIWrapper
from langchain.agents import initialize_agent

if __name__ == '__main__':

    llm = ChatOpenAI(temperature=0)
    langchain.debug = False

    search = SerpAPIWrapper()

    tools = [
        Tool(
            name="Current Search",
            func=search.run,
            description="useful for when you need to answer questions about current events or the current state of the world"
        ),
    ]

    memory = ConversationBufferMemory(memory_key="chat_history")

    agent_chain = initialize_agent(tools=tools, llm=llm, agent=AgentType.STRUCTURED_CHAT_ZERO_SHOT_REACT_DESCRIPTION, verbose=True)

    agent_chain.run("I want to know the weather in New York.")