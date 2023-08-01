from langchain.chains.question_answering import load_qa_chain
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import Chroma

from langchain.document_loaders import DirectoryLoader


def load_all_courses(path):
    loader = DirectoryLoader(path, glob='*.md')
    return loader.load()


if __name__ == '__main__':
    persist_directory = 'chroma_storage'

    # docs = load_all_courses("docs")
    # print(f'You have {len(docs)} document(s) in your data')
    # print(f'There are {len(docs[0].page_content)} characters in your document')
    #
    # from langchain.text_splitter import RecursiveCharacterTextSplitter
    #
    # text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
    # split_docs = text_splitter.split_documents(docs)
    # print(f'Now you have {len(split_docs)} documents')
    #
    embeddings = OpenAIEmbeddings()
    # vectorstore = Chroma.from_documents(split_docs, embeddings, persist_directory=persist_directory)
    # vectorstore.persist()

    vectordb = Chroma(persist_directory=persist_directory, embedding_function=embeddings)

    query = "如何利用Solidity实现插入排序？"
    docs = vectordb.similarity_search(query, k=1)

    print(len(docs))

    print(docs[0])

    from langchain.llms import OpenAI
    llm = OpenAI()

    chain = load_qa_chain(llm=llm)
    print(chain.run(input_documents=docs, question=query))
