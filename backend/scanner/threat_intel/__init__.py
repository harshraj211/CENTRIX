"""
Wraith Threat Intelligence RAG Pipeline
========================================
Local, privacy-preserving vulnerability analysis using Ollama + ChromaDB.

Sub-modules
-----------
- config        : Env-based configuration
- ollama_client : Async Ollama inference with fallback
- embedder      : Local embedding via Ollama nomic-embed-text
- vector_store  : ChromaDB persistence layer
- normalizer    : Advisory parsing / chunking
- feeds         : NVD, GHSA, CISA-KEV ingestion with rate-limit / backoff
- sync_worker   : APScheduler background sync job
- rag_engine    : Retrieval-Augmented Generation query interface
"""
