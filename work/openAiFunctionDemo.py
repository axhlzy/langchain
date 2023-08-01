import yfinance as yf
from datetime import datetime, timedelta

import langchain
from work.tools.cmd.base import get_top_activity_info
from work.tools.frida import frida_findBaseAddress, frida_ps, frida_spawn, frida_attach, frida_load_js_code, \
    frida_exec_js_code_method
from work.tools.frida.java import generate_java_hook_code


def get_current_stock_price(ticker):
    """Method to get current stock price"""

    ticker_data = yf.Ticker(ticker)
    recent = ticker_data.history(period='1d')
    return {
        'price': recent.iloc[0]['Close'],
        'currency': ticker_data.info['currency']
    }


def get_stock_performance(ticker, days):
    """Method to get stock price change in percentage"""

    past_date = datetime.today() - timedelta(days=days)
    ticker_data = yf.Ticker(ticker)
    history = ticker_data.history(start=past_date)
    old_price = history.iloc[0]['Close']
    current_price = history.iloc[-1]['Close']
    # return {
    #     'percent_change': ((current_price - old_price)/old_price)*100
    #     }
    return "percent_change {} %".format(((current_price - old_price) / old_price) * 100)


from typing import Type
from pydantic import BaseModel, Field
from langchain.tools import BaseTool, ShellTool, JsonListKeysTool


class CurrentStockPriceInput(BaseModel):
    """Inputs for get_current_stock_price"""
    ticker: str = Field(description="Ticker symbol of the stock")


class CurrentStockPriceTool(BaseTool):
    name = "get_current_stock_price"
    description = """
        Useful when you want to get current stock price.
        You should enter the stock ticker symbol recognized by the yahoo finance
        """
    args_schema: Type[BaseModel] = CurrentStockPriceInput

    def _run(self, ticker: str):
        price_response = get_current_stock_price(ticker)
        return price_response

    def _arun(self, ticker: str):
        raise NotImplementedError("get_current_stock_price does not support async")


class StockPercentChangeInput(BaseModel):
    """Inputs for get_stock_performance"""
    ticker: str = Field(description="Ticker symbol of the stock")
    days: int = Field(description='Timedelta days to get past date from current date')


class StockPerformanceTool(BaseTool):
    name = "get_stock_performance"
    description = """
        Useful when you want to check performance of the stock.
        You should enter the stock ticker symbol recognized by the yahoo finance.
        You should enter days as number of days from today from which performance needs to be check.
        output will be the change in the stock price represented as a percentage.
        """
    args_schema: Type[BaseModel] = StockPercentChangeInput

    def _run(self, ticker: str, days: int):
        response = get_stock_performance(ticker, days)
        return response

    def _arun(self, ticker: str):
        raise NotImplementedError("get_stock_performance does not support async")


from langchain.agents import AgentType, load_tools
from langchain.chat_models import ChatOpenAI
from langchain.agents import initialize_agent
from langchain.memory import ConversationBufferMemory

llm = ChatOpenAI(
    model="gpt-3.5-turbo-0613",
    temperature=0
)
langchain.debug = False

from langchain.prompts import MessagesPlaceholder
from langchain.memory import ConversationBufferMemory

agent_kwargs = {
    "extra_prompt_messages": [MessagesPlaceholder(variable_name="memory")],
}

memory = ConversationBufferMemory(memory_key="memory", return_messages=True)

if __name__ == '__main__':
    # tools = [generate_java_hook_code(), frida_attach(), frida_load_js_code(), frida_exec_js_code_method()]
    tools = [ShellTool(), ]


    agent = initialize_agent(tools=tools, llm=llm,
                             agent=AgentType.OPENAI_FUNCTIONS,
                             agent_kwargs=agent_kwargs,
                             memory=memory,
                             verbose=True)

    # attach 猜猜我谁 then genereate some js code to hook all methods of this class : com.unity3d.player.UnityPlayer,print their parameters
    while True:
        print(agent.run(input(">")))
