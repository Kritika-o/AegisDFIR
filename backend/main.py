import os
from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, Response
from pydantic import BaseModel
from typing import List, Dict, Any

from backend.parser import load_all_evidence, ForensicEvent
from backend.search import SearchEngine
from backend.llm import GroundedAnalyst
from backend.reporter import generate_markdown_report, generate_html_report
from backend.literature_data import LITERATURE_PAPERS

app = FastAPI(title="AI-Powered Forensic Assistant API", version="1.0.0")

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for state
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))

all_events: List[ForensicEvent] = []
search_engine: SearchEngine = None
analyst = GroundedAnalyst()

class QueryRequest(BaseModel):
    query: str
    top_k: int = 5
    sparse_weight: float = 0.5

class ChatRequest(BaseModel):
    query: str
    retrieved_indices: List[int] = []  # List of event indices in all_events

class ReportRequest(BaseModel):
    case_name: str
    investigator: str

@app.on_event("startup")
def startup_event():
    """Initializes and loads sample forensic files on startup."""
    global all_events, search_engine
    all_events = load_all_evidence(DATA_DIR)
    search_engine = SearchEngine(all_events)
    print(f"Server Startup: Ingested {len(all_events)} events from data directory.")

@app.post("/api/ingest")
def ingest_logs():
    """Simulates reloading and parsing forensic logs from the data directory."""
    global all_events, search_engine
    try:
        all_events = load_all_evidence(DATA_DIR)
        search_engine = SearchEngine(all_events)
        
        # Aggregate statistics
        stats = {
            "status": "success",
            "message": f"Successfully parsed and ingested forensic evidence.",
            "total_events": len(all_events),
            "sources": list(set(ev.source_file for ev in all_events)),
            "endpoints": list(set(ev.hostname for ev in all_events)),
            "timeline_bounds": {
                "start": all_events[0].timestamp if all_events else None,
                "end": all_events[-1].timestamp if all_events else None
            }
        }
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/events")
def get_all_events():
    """Returns all ingested forensic events chronologically."""
    return [ev.to_dict() for ev in all_events]

@app.post("/api/search")
def hybrid_search(payload: QueryRequest):
    """Executes a hybrid search (sparse BM25 + dense TF-IDF semantic match)."""
    global search_engine
    if not search_engine:
        raise HTTPException(status_code=400, detail="Search engine is not initialized. Run ingestion first.")
    
    results = search_engine.search(
        query=payload.query,
        top_k=payload.top_k,
        sparse_weight=payload.sparse_weight
    )
    
    formatted_results = []
    for ev, score in results:
        # Find index in global events for context binding
        g_idx = next((i for i, x in enumerate(all_events) if x.timestamp == ev.timestamp and x.line_number == ev.line_number), -1)
        formatted_results.append({
            "global_index": g_idx,
            "score": round(score, 4),
            "event": ev.to_dict()
        })
        
    return formatted_results

@app.post("/api/chat")
def chat_with_analyst(payload: ChatRequest):
    """Routes query with grounding retrieved events to the LLM expert pipeline."""
    global all_events, analyst
    if not all_events:
        raise HTTPException(status_code=400, detail="No forensic context loaded. Ingest data first.")
    
    # Extract the grounded events requested by the front-end (or default to top matches if empty)
    context_events = []
    if payload.retrieved_indices:
        for idx in payload.retrieved_indices:
            if 0 <= idx < len(all_events):
                context_events.append(all_events[idx])
    else:
        # If no explicit contexts provided, auto-retrieve top 5 context elements using hybrid search
        if search_engine:
            matches = search_engine.search(payload.query, top_k=5)
            context_events = [ev for ev, _ in matches]

    # Generate grounded answer
    answer = analyst.answer_question(payload.query, context_events)
    return {
        "answer": answer,
        "grounded_events": [ev.to_dict() for ev in context_events]
    }

@app.get("/api/literature")
def get_literature():
    """Exposes the 15-paper literature database completed in Week 1."""
    return LITERATURE_PAPERS

@app.post("/api/report")
def generate_report(payload: ReportRequest):
    """Compiles the forensic incident correlation report."""
    global all_events
    if not all_events:
        raise HTTPException(status_code=400, detail="No evidence events loaded. Ingest data first.")
        
    markdown_content = generate_markdown_report(all_events, payload.case_name, payload.investigator)
    html_content = generate_html_report(all_events, payload.case_name, payload.investigator)
    
    return {
        "markdown": markdown_content,
        "html": html_content
    }

# Serve frontend application with no-cache headers to always deliver fresh HTML
@app.get("/")
def get_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            content = f.read()
        return Response(
            content=content,
            media_type="text/html",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
    return HTMLResponse("<h2>Frontend not found. Ensure frontend/index.html exists.</h2>")
