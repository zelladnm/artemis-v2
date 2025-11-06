# src/knowledge_base/vector_store.py (v2.0 - with Add Documents capability)
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class VectorStoreManager:
    def __init__(self, config: dict):
        self.config = config
        self.embedding_model_name = config['embedding_model']
        self.persist_directory = str(Path(config['data_paths']['vector_db']))
        self.collection_name = config['collection_name']

        logging.info(f"Initializing embeddings with model: {self.embedding_model_name}")
        self.embeddings = HuggingFaceEmbeddings(
            model_name=self.embedding_model_name,
            model_kwargs={'device': 'cpu'}
        )

        # 初始化时就加载数据库实例
        self.vector_store = Chroma(
            persist_directory=self.persist_directory,
            embedding_function=self.embeddings,
            collection_name=self.collection_name
        )

    def add_documents(self, documents: list[Document]):
        """
        将新的文档列表增量添加到现有的向量数据库中。
        """
        if not documents:
            logging.warning("No new documents to add. Skipping.")
            return 0

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=self.config['chunk_size'],
            chunk_overlap=self.config['chunk_overlap']
        )
        splits = text_splitter.split_documents(documents)

        logging.info(f"Adding {len(splits)} new document chunks to the vector store...")
        self.vector_store.add_documents(splits)
        logging.info("Successfully added new documents to the vector store.")
        return len(splits)

    def get_retriever(self):
        """获取一个配置好的检索器"""
        return self.vector_store.as_retriever()

    def get_vector_count(self) -> int:
        """获取数据库中的向量总数"""
        try:
            return self.vector_store._collection.count()
        except Exception:
            return 0