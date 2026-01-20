# backend/app/main.py
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
import json
from .parser import analyze_log_lines
from .db import SessionLocal, engine
from .models import Base, Report

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log Analyzer API")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

OUTPUT_DIR = Path(__file__).resolve().parents[2] / "output"
LOGS_DIR = Path(__file__).resolve().parents[2] / "logs"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)

@app.post("/api/reports/generate")
async def generate_report(file: UploadFile | None = File(None), suspicious_threshold: int = 10):
    # read lines either from uploaded file or default logs/apache_access.log
    if file:
        raw = (await file.read()).decode("utf-8", errors="ignore").splitlines()
    else:
        default_log = LOGS_DIR / "apache_access.log"
        if not default_log.exists():
            raise HTTPException(404, "No log file found in logs/apache_access.log and no file uploaded.")
        raw = default_log.read_text(encoding="utf-8", errors="ignore").splitlines()

    summary = analyze_log_lines(raw, suspicious_threshold=suspicious_threshold)

    # persist report in DB
    db = SessionLocal()
    r = Report(name="report", summary_json=json.dumps(summary))
    db.add(r)
    db.commit()
    db.refresh(r)

    # write a human-friendly text file
    out_path = OUTPUT_DIR / f"soc_report_{r.id}.txt"
    with out_path.open("w", encoding="utf-8") as f:
        f.write("==== SOC ANALYST REPORT ====\n\n")
        f.write("Top IPs:\n")
        for ip, cnt in summary["top_ips"]:
            f.write(f"{ip} -> {cnt}\n")
        f.write("\nSuspicious UAs:\n")
        for ua, cnt in summary["suspicious_uas"][:50]:
            f.write(f"{ua} -> {cnt}\n")

    r.filename = str(out_path.name)
    db.add(r)
    db.commit()
    db.close()
    return {"report_id": r.id, "filename": r.filename}

@app.get("/api/reports")
def list_reports():
    db = SessionLocal()
    rows = db.query(Report).order_by(Report.created_at.desc()).all()
    db.close()
    return [{"id": r.id, "name": r.name, "created_at": r.created_at.isoformat(), "filename": r.filename} for r in rows]

@app.get("/api/reports/{report_id}")
def get_report(report_id: int):
    db = SessionLocal()
    r = db.query(Report).get(report_id)
    db.close()
    if not r:
        raise HTTPException(404, "Report not found")
    return {"id": r.id, "name": r.name, "created_at": r.created_at.isoformat(), "summary": json.loads(r.summary_json)}

# optional: return the text file:
from fastapi.responses import FileResponse
@app.get("/api/reports/{report_id}/download")
def download_report(report_id: int):
    db = SessionLocal()
    r = db.query(Report).get(report_id)
    db.close()
    if not r or not r.filename:
        raise HTTPException(404, "Report file not found")
    path = OUTPUT_DIR / r.filename
    return FileResponse(path, media_type="text/plain", filename=r.filename)
