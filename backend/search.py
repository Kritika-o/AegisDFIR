import re
import math
from typing import List, Dict, Any, Tuple
from backend.parser import ForensicEvent

def tokenize(text: str) -> List[str]:
    """Tokenizes text into clean lowercase alphanumeric words."""
    if not text:
        return []
    # Lowercase and split by non-alphanumeric characters
    tokens = re.findall(r'[a-zA-Z0-9_\-\\./]+', text.lower())
    return tokens

class SearchEngine:
    def __init__(self, events: List[ForensicEvent]):
        self.events = events
        self.bm25_index = {}
        self.doc_lengths = []
        self.avg_doc_len = 0.0
        
        # TF-IDF structures for semantic matching
        self.vocabulary = set()
        self.tf_idf_vectors = []
        self.idf = {}

        if events:
            self._build_bm25_index()
            self._build_semantic_index()

    def _build_bm25_index(self):
        """Builds sparse lookup for exact terms (IPs, hashes, event IDs)."""
        self.doc_lengths = [len(tokenize(ev.description) + tokenize(ev.hostname) + tokenize(ev.username)) for ev in self.events]
        self.avg_doc_len = sum(self.doc_lengths) / len(self.doc_lengths) if self.doc_lengths else 1.0

        for idx, ev in enumerate(self.events):
            # Combine fields to index
            text_to_index = f"{ev.description} {ev.hostname} {ev.username} {ev.event_id} {ev.source_file}"
            tokens = tokenize(text_to_index)
            
            # Count terms in this document
            term_freqs = {}
            for t in tokens:
                term_freqs[t] = term_freqs.get(t, 0) + 1
                
            # Add to inverted index
            for term, freq in term_freqs.items():
                if term not in self.bm25_index:
                    self.bm25_index[term] = []
                self.bm25_index[term].append((idx, freq))

    def _build_semantic_index(self):
        """Builds TF-IDF vector space for semantic similarity searches."""
        # 1. Collect vocabulary and term frequencies across all docs
        doc_term_freqs = []
        doc_count = len(self.events)
        
        for ev in self.events:
            tokens = tokenize(ev.description)
            freqs = {}
            for t in tokens:
                freqs[t] = freqs.get(t, 0) + 1
                self.vocabulary.add(t)
            doc_term_freqs.append(freqs)
            
        # 2. Compute IDF for vocabulary
        for term in self.vocabulary:
            docs_with_term = sum(1 for freqs in doc_term_freqs if term in freqs)
            # Standard IDF formula
            self.idf[term] = math.log((doc_count - docs_with_term + 0.5) / (docs_with_term + 0.5) + 1.0)
            if self.idf[term] < 0:
                self.idf[term] = 0.0

        # 3. Create document TF-IDF vectors
        for idx, freqs in enumerate(doc_term_freqs):
            vector = {}
            for term, tf in freqs.items():
                vector[term] = tf * self.idf[term]
            
            # Normalize vector (L2 norm)
            norm = math.sqrt(sum(val ** 2 for val in vector.values()))
            if norm > 0:
                for term in vector:
                    vector[term] /= norm
            self.tf_idf_vectors.append(vector)

    def bm25_score(self, query_tokens: List[str], k1=1.5, b=0.75) -> Dict[int, float]:
        """Computes BM25 sparse retrieval score for each document."""
        scores = {}
        doc_count = len(self.events)

        for term in query_tokens:
            if term not in self.bm25_index:
                continue
                
            # Calculate term IDF
            matching_docs = self.bm25_index[term]
            n_q = len(matching_docs)
            idf = math.log((doc_count - n_q + 0.5) / (n_q + 0.5) + 1.0)
            if idf < 0:
                idf = 0.0001
                
            # Calculate score contributions
            for doc_idx, freq in matching_docs:
                doc_len = self.doc_lengths[doc_idx]
                numerator = freq * (k1 + 1)
                denominator = freq + k1 * (1 - b + b * (doc_len / self.avg_doc_len))
                term_score = idf * (numerator / denominator)
                scores[doc_idx] = scores.get(doc_idx, 0.0) + term_score

        return scores

    def semantic_score(self, query_tokens: List[str]) -> Dict[int, float]:
        """Computes dense/semantic-like similarity scores via TF-IDF cosine similarity."""
        scores = {}
        
        # Build query TF-IDF vector
        query_vector = {}
        for t in query_tokens:
            if t in self.vocabulary:
                query_vector[t] = query_vector.get(t, 0) + 1

        # Multiply by IDF and normalize query vector
        for t in query_vector:
            query_vector[t] *= self.idf[t]
            
        q_norm = math.sqrt(sum(val ** 2 for val in query_vector.values()))
        if q_norm > 0:
            for t in query_vector:
                query_vector[t] /= q_norm
        else:
            return {}

        # Compute cosine similarity with each document vector
        for idx, doc_vector in enumerate(self.tf_idf_vectors):
            dot_product = sum(query_vector[t] * doc_vector.get(t, 0.0) for t in query_vector if t in doc_vector)
            if dot_product > 0.01:
                scores[idx] = dot_product

        return scores

    def search(self, query: str, top_k=5, sparse_weight=0.5) -> List[Tuple[ForensicEvent, float]]:
        """Executes hybrid retrieval combining Sparse (BM25) and Semantic search."""
        if not self.events:
            return []

        query_tokens = tokenize(query)
        if not query_tokens:
            # Return chronological if query is empty
            return [(ev, 1.0) for ev in self.events[:top_k]]

        # Get scores from both pipelines
        bm25_results = self.bm25_score(query_tokens)
        semantic_results = self.semantic_score(query_tokens)

        # Min-max normalization for fusion
        def normalize_scores(score_dict: Dict[int, float]) -> Dict[int, float]:
            if not score_dict:
                return {}
            min_s = min(score_dict.values())
            max_s = max(score_dict.values())
            if max_s == min_s:
                return {k: 1.0 for k in score_dict}
            return {k: (v - min_s) / (max_s - min_s) for k, v in score_dict.items()}

        norm_bm25 = normalize_scores(bm25_results)
        norm_semantic = normalize_scores(semantic_results)

        # Combine scores
        hybrid_scores = {}
        all_indices = set(norm_bm25.keys()) | set(norm_semantic.keys())
        
        for idx in all_indices:
            s_sparse = norm_bm25.get(idx, 0.0)
            s_dense = norm_semantic.get(idx, 0.0)
            # Weighted average
            hybrid_scores[idx] = sparse_weight * s_sparse + (1.0 - sparse_weight) * s_dense

        # Sort by final score descending
        sorted_indices = sorted(hybrid_scores.items(), key=lambda x: x[1], reverse=True)
        
        results = []
        for idx, score in sorted_indices[:top_k]:
            results.append((self.events[idx], score))
            
        return results
