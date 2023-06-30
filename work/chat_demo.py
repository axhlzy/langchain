from langchain.chains import ConversationChain
from langchain.chat_models import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.prompts import ChatPromptTemplate, HumanMessagePromptTemplate, MessagesPlaceholder

if __name__ == '__main__':
    chat = ChatOpenAI(temperature=0, model_name="gpt-3.5-turbo-0613")
    template = """{input_message}?"""
    chat_prompt = ChatPromptTemplate.from_messages([
        MessagesPlaceholder(variable_name="history"),
        HumanMessagePromptTemplate.from_template("{input}")
    ])
    memory = ConversationBufferMemory(return_messages=True)

    conversation = ConversationChain(llm=chat, prompt=chat_prompt, memory=memory, verbose=True)

    print(conversation.predict(input="生命的意义是什么吗"))

    while True:
        input_message = input(">")
        print(conversation.predict(input=input_message))