"""RAG retrieval for NI calibration responses using vector similarity."""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

import numpy as np

from models import CalibrationResponse, DriftPatternType

logger = logging.getLogger(__name__)


class CalibrationRAGRetriever:
    """Vector-based retrieval for matching calibration responses.

    Uses Qdrant or FAISS for semantic similarity matching against
    the 1000 Namas response library.
    """

    def __init__(
        self,
        embedding_model_name: str = "all-MiniLM-L6-v2",
        vector_db_type: str = "faiss",
    ):
        self._embedding_model_name = embedding_model_name
        self._vector_db_type = vector_db_type
        self._embedder = None
        self._index = None
        self._id_map: Dict[int, str] = {}

    def initialize(self) -> None:
        """Initialize embedding model and vector index."""
        try:
            from sentence_transformers import SentenceTransformer
            self._embedder = SentenceTransformer(self._embedding_model_name)
            logger.info(f"Loaded embedding model: {self._embedding_model_name}")
        except ImportError:
            logger.warning("sentence-transformers not available; RAG disabled")
            return

        if self._vector_db_type == "faiss":
            self._init_faiss()
        elif self._vector_db_type == "qdrant":
            self._init_qdrant()

    def _init_faiss(self) -> None:
        try:
            import faiss
            # Will be populated when responses are indexed
            self._faiss_dimension = 384  # MiniLM-L6-v2 dimension
            self._index = faiss.IndexFlatIP(self._faiss_dimension)
            logger.info("FAISS index initialized")
        except ImportError:
            logger.warning("FAISS not available")

    def _init_qdrant(self) -> None:
        try:
            from qdrant_client import QdrantClient
            from qdrant_client.models import Distance, VectorParams
            self._qdrant = QdrantClient(host="localhost", port=6333)
            self._qdrant.recreate_collection(
                collection_name="calibration_responses",
                vectors_config=VectorParams(size=384, distance=Distance.COSINE),
            )
            logger.info("Qdrant collection initialized")
        except ImportError:
            logger.warning("Qdrant client not available")

    def index_responses(self, responses: List[CalibrationResponse]) -> int:
        """Index calibration responses for vector retrieval."""
        if not self._embedder:
            return 0

        texts = []
        ids = []
        for i, resp in enumerate(responses):
            text = (
                f"{resp.drift_pattern.value} {resp.organizational_context} "
                f"{resp.role_context} {resp.moment_context} {resp.response_text}"
            )
            texts.append(text)
            ids.append(str(resp.id))

        embeddings = self._embedder.encode(texts, normalize_embeddings=True)

        if self._vector_db_type == "faiss" and self._index is not None:
            import faiss
            self._index.reset()
            self._index.add(np.array(embeddings, dtype=np.float32))
            for i, resp_id in enumerate(ids):
                self._id_map[i] = resp_id
        elif self._vector_db_type == "qdrant":
            from qdrant_client.models import PointStruct
            points = [
                PointStruct(
                    id=i, vector=emb.tolist(), payload={"response_id": rid}
                )
                for i, (emb, rid) in enumerate(zip(embeddings, ids))
            ]
            self._qdrant.upsert(
                collection_name="calibration_responses", points=points
            )

        logger.info(f"Indexed {len(texts)} calibration responses")
        return len(texts)

    def search(
        self,
        query: str,
        drift_pattern: Optional[DriftPatternType] = None,
        top_k: int = 5,
    ) -> List[str]:
        """Search for matching calibration response IDs."""
        if not self._embedder:
            return []

        query_text = query
        if drift_pattern:
            query_text = f"{drift_pattern.value} {query}"

        query_emb = self._embedder.encode([query_text], normalize_embeddings=True)

        if self._vector_db_type == "faiss" and self._index is not None:
            if self._index.ntotal == 0:
                return []
            k = min(top_k, self._index.ntotal)
            distances, indices = self._index.search(
                np.array(query_emb, dtype=np.float32), k
            )
            return [self._id_map[int(idx)] for idx in indices[0] if int(idx) in self._id_map]

        elif self._vector_db_type == "qdrant":
            results = self._qdrant.search(
                collection_name="calibration_responses",
                query_vector=query_emb[0].tolist(),
                limit=top_k,
            )
            return [r.payload["response_id"] for r in results]

        return []
