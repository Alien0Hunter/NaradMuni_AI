import os
from langchain_community.vectorstores import Chroma
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.chat_models import ChatOpenAI
from langchain.chains import RetrievalQA
from langchain.document_loaders import DirectoryLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from dotenv import load_dotenv

load_dotenv()

def create_vector_db(data_path="data", persist_dir="chroma_db"):
    loader = DirectoryLoader(data_path)
    documents = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    texts = text_splitter.split_documents(documents)
    embeddings = OpenAIEmbeddings()
    vectordb = Chroma.from_documents(texts, embeddings, persist_directory=persist_dir)
    vectordb.persist()
    return vectordb

def ask_naradmuni(question, persist_dir="chroma_db"):
    vectordb = Chroma(persist_directory=persist_dir, embedding_function=OpenAIEmbeddings())
    llm = ChatOpenAI(model_name="gpt-4", temperature=0.2)
    qa = RetrievalQA.from_chain_type(llm=llm, retriever=vectordb.as_retriever())
    return qa.run(question)