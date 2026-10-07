# AegisDFIR: AI-Powered Forensic Assistant

An LLM-grounded digital forensics Q&A and automated report generation system, built as part of the Summer Internship Programme, School of Computer Science and Engineering, RV University.

Every answer AegisDFIR gives is strictly grounded in ingested forensic evidence and carries an inline citation (`[filename:lineNumber]`) back to the exact source log line — the system is explicitly designed to decline rather than speculate when evidence is insufficient.

## Team

- **Kritika Kulkarni** — National Forensic Sciences University, Dharwad


**Guide:** Dr. Manish Kumar, Professor, School of Computer Science and Engineering, RV University

## Features

- **Hierarchical, event-aware chunking** — logs are split by event boundary, not by fixed character count, preserving Timestamp, Hostname, User Account, and Event ID as first-class metadata.
- **Hybrid retrieval** — BM25 (sparse/exact-match) fused with TF-IDF (semantic) search, so both indicators of compromise (IPs, hashes) and conceptual queries are answered accurately.
- **Citation-grounded generation** — a locally-hosted LLM (via [Ollama](https://ollama.com)) answers only from retrieved evidence, with a three-tier fallback (local LLM → optional cloud API → deterministic rule-based responder) so the system never fails outright.
- **Automated report generation** — one-click compilation of the full investigation into a Markdown/HTML incident report (Executive Summary, Timeline, Evidence Inventory, IOCs), sealed with an MD5 integrity checksum.
- **Fully offline-capable** — designed for air-gapped forensic environments; no case data leaves the machine when using local inference.

## Architecture

```
Ingestion → Indexing → Retrieval → Generation → Interface → Reporting
```

| Stage | Module | Description |
|---|---|---|
| Ingestion | `backend/parser.py` | Parses raw EVTX/MFT artifacts into normalised, metadata-tagged events |
| Indexing/Retrieval | `backend/search.py` | Hybrid BM25 + TF-IDF retrieval engine |
| Generation | `backend/llm.py` | Grounded LLM pipeline with local/cloud/rule-based fallback chain |
| Interface | `frontend/index.html` | Single-page dashboard: Dashboard, Evidence Ingest, Hybrid Explorer, Chat Analyst, Literature Hub, Report Compiler |
| Reporting | `backend/reporter.py` | Markdown/HTML report compiler with MD5 integrity seal |

## Getting Started

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed, with a model pulled (e.g. `ollama pull qwen2.5:3b`)

### Run (Windows)
```
run.bat
```
This creates/activates a virtual environment, installs dependencies, and launches the app at `http://127.0.0.1:8000`.

### Run (manual / any OS)
```bash
pip install -r requirements.txt
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

## Project Structure

```
AegisDFIR/
├── backend/
│   ├── main.py            # FastAPI app and API routes
│   ├── parser.py          # EVTX/MFT ingestion
│   ├── search.py          # Hybrid BM25 + TF-IDF retrieval engine
│   ├── llm.py             # Grounded LLM pipeline (Ollama + fallbacks)
│   ├── reporter.py        # Report generation (Markdown/HTML)
│   └── literature_data.py # Literature survey data
├── frontend/
│   └── index.html         # Single-page dashboard UI
├── data/
│   ├── sample_evtx.json   # Seeded sample Windows Event Log data
│   └── sample_mft.csv     # Seeded sample MFT data
├── requirements.txt
└── run.bat
```

## Validation

A blind-test validation pass caught and corrected a real citation-grounding defect during development — see Section 7.2.2 of the project report for the full case study. This is treated as a positive validation outcome, demonstrating that the testing methodology successfully catches the class of failure (fabricated evidentiary attribution) identified as the central risk of LLM-assisted forensics in the accompanying literature survey.

## Documentation

The full project report and presentation (LaTeX source, PDF, and editable Word/PowerPoint versions) are maintained separately as part of the internship submission.

## Future Work

- Migrate retrieval to a dedicated vector database (Qdrant/Milvus) with dense embeddings for multi-GB scale
- Add multi-turn conversational memory
- Extend ingestion to volatile memory (.raw) images and packet captures (.pcap)
- Build a formal benchmarking harness for citation precision/recall
