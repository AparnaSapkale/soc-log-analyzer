# backend/app/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
import datetime
import json

Base = declarative_base()

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    name = Column(String(255))
    filename = Column(String(255))   # optional saved text filename
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    summary_json = Column(Text)      # JSON text with analysis 

