import os
import json
import csv
from typing import List, Dict, Any
from datetime import datetime

class ForensicEvent:
    def __init__(
        self,
        timestamp: str,
        source_file: str,
        line_number: int,
        event_type: str,  # "EVTX" or "MFT"
        event_id: str,    # e.g., "4624", "MFT_CREATED"
        hostname: str,
        username: str,
        description: str,
        metadata: Dict[str, Any]
    ):
        self.timestamp = timestamp
        self.source_file = source_file
        self.line_number = line_number
        self.event_type = event_type
        self.event_id = event_id
        self.hostname = hostname
        self.username = username
        self.description = description
        self.metadata = metadata

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "hostname": self.hostname,
            "username": self.username,
            "description": self.description,
            "metadata": self.metadata
        }

def parse_evtx_json(file_path: str) -> List[ForensicEvent]:
    """Parses sample EVTX log data in JSON format."""
    events = []
    if not os.path.exists(file_path):
        return events

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for item in data:
                # Extract metadata fields for hybrid indexing
                details = item.get("details", "")
                metadata = {}
                
                # Check for IP addresses or port numbers in details
                if "Source Network Address:" in details:
                    parts = details.split("Source Network Address:")
                    ip = parts[1].split(".")[0:4] # handle cases
                    # simple parser
                    import re
                    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', details)
                    if ip_match:
                        metadata["ip_address"] = ip_match.group(0)
                
                if "CommandLine:" in details:
                    parts = details.split("CommandLine:")
                    cmd = parts[1].strip().split("Parent Process:")[0].strip()
                    metadata["command_line"] = cmd

                if "Service Name:" in details:
                    import re
                    name_match = re.search(r'Service Name:\s*(\w+)', details)
                    if name_match:
                        metadata["service_name"] = name_match.group(1)
                    file_match = re.search(r'Service File Name:\s*([^\n\r]+)', details)
                    if file_match:
                        metadata["service_file"] = file_match.group(1).strip()

                events.append(ForensicEvent(
                    timestamp=item.get("timestamp"),
                    source_file=item.get("file", "unknown.evtx"),
                    line_number=item.get("line_number", 0),
                    event_type="EVTX",
                    event_id=str(item.get("event_id", "")),
                    hostname=item.get("computer", "UNKNOWN"),
                    username=item.get("username", "UNKNOWN"),
                    description=details,
                    metadata=metadata
                ))
    except Exception as e:
        print(f"Error parsing EVTX: {e}")
    
    return events

def parse_mft_csv(file_path: str) -> List[ForensicEvent]:
    """Parses sample MFT records in CSV format."""
    events = []
    if not os.path.exists(file_path):
        return events

    try:
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                action = row.get("action", "").upper()
                event_id = f"MFT_{action}"
                filepath = row.get("filepath", "")
                filename = os.path.basename(filepath)
                size_bytes = row.get("size_bytes", "0")
                md5 = row.get("md5", "")

                metadata = {
                    "filepath": filepath,
                    "filename": filename,
                    "size_bytes": int(size_bytes) if size_bytes.isdigit() else 0,
                    "md5": md5
                }

                description = f"File {action.lower()}: {filepath} (Size: {size_bytes} bytes). MD5: {md5 if md5 else 'N/A'}"
                
                events.append(ForensicEvent(
                    timestamp=row.get("timestamp"),
                    source_file=row.get("file", "MFT.csv"),
                    line_number=int(row.get("line_number", 0)) if row.get("line_number", "").isdigit() else 0,
                    event_type="MFT",
                    event_id=event_id,
                    hostname="DESKTOP-HR01",  # MFT is from the endpoint
                    username="SYSTEM",         # Filesystem changes are logged generally
                    description=description,
                    metadata=metadata
                ))
    except Exception as e:
        print(f"Error parsing MFT: {e}")

    return events

def load_all_evidence(data_dir: str) -> List[ForensicEvent]:
    """Loads and aggregates all forensic events from data directory."""
    evtx_path = os.path.join(data_dir, "sample_evtx.json")
    mft_path = os.path.join(data_dir, "sample_mft.csv")
    
    events = []
    events.extend(parse_evtx_json(evtx_path))
    events.extend(parse_mft_csv(mft_path))
    
    # Sort events by timestamp (chronological)
    events.sort(key=lambda x: x.timestamp)
    return events
