#!/usr/bin/env python3
"""
FastAPI web application for Gmail Spam Killer.
Provides a web UI to run spam detection and manage emails.
"""

import json
import os
import asyncio
from typing import List, Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# Import our spam killer
from gmail_spam_killer import GmailSpamKiller

app = FastAPI(title="Gmail Spam Killer", description="AI-powered spam detection and management")

# Templates
templates = Jinja2Templates(directory="templates")

# Global instance of spam killer
spam_killer = None
scan_status = {
    'scanning': False,
    'progress': 0,
    'total': 0,
    'current_email': '',
    'results': []
}

# Pydantic models
class ScanRequest(BaseModel):
    max_emails: int = 20

class ArchiveRequest(BaseModel):
    email_id: str
    unsubscribe: bool = False
    unsubscribe_links: List[str] = []

class EmailResult(BaseModel):
    email_id: str
    subject: str
    sender: str
    body_preview: str
    is_spam: bool
    reason: str
    unsubscribe_links: List[str] = []

class StatusResponse(BaseModel):
    authenticated: bool
    message: str

class ScanResponse(BaseModel):
    success: bool
    message: str
    total_emails: int = 0

class ArchiveResponse(BaseModel):
    success: bool
    message: str
    email_id: str
    unsubscribe_success: int = 0

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Main page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/status", response_model=StatusResponse)
async def get_status():
    """Check if spam killer is authenticated."""
    global spam_killer
    if spam_killer is None:
        return StatusResponse(authenticated=False, message="Not initialized")
    
    try:
        if spam_killer.service is None:
            return StatusResponse(authenticated=False, message="Not authenticated")
        return StatusResponse(authenticated=True, message="Ready")
    except Exception as e:
        return StatusResponse(authenticated=False, message=str(e))

@app.post("/api/authenticate")
async def authenticate():
    """Initialize and authenticate spam killer."""
    global spam_killer
    try:
        spam_killer = GmailSpamKiller()
        if spam_killer.authenticate_gmail():
            return {"success": True, "message": "Authenticated successfully"}
        else:
            return {"success": False, "message": "Authentication failed"}
    except Exception as e:
        return {"success": False, "message": str(e)}

@app.get("/api/scan/status")
async def get_scan_status():
    """Get current scan status."""
    return scan_status

@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(scan_request: ScanRequest):
    """Start scanning emails for spam."""
    global spam_killer, scan_status
    
    if spam_killer is None or spam_killer.service is None:
        raise HTTPException(status_code=400, detail="Not authenticated. Please authenticate first.")
    
    if scan_status['scanning']:
        raise HTTPException(status_code=400, detail="Scan already in progress")
    
    # Reset scan status
    scan_status.update({
        'scanning': True,
        'progress': 0,
        'total': 0,
        'current_email': 'Initializing...',
        'results': []
    })
    
    # Start background scan
    asyncio.create_task(run_scan(scan_request.max_emails))
    
    return ScanResponse(
        success=True, 
        message="Scan started", 
        total_emails=scan_request.max_emails
    )

async def run_scan(max_emails: int):
    """Run the email scan in background."""
    global spam_killer, scan_status
    
    try:
        scan_status['current_email'] = f'Fetching up to {max_emails} emails...'
        
        # Fetch emails
        emails = spam_killer.get_recent_emails(max_emails)
        inbox_emails = [(i, email) for i, email in enumerate(emails) if 'INBOX' in email['labels']]
        
        if not inbox_emails:
            scan_status.update({
                'scanning': False,
                'current_email': 'No emails in inbox to process.'
            })
            return
        
        scan_status.update({
            'total': len(inbox_emails),
            'current_email': f'Analyzing {len(inbox_emails)} emails...'
        })
        
        # Process emails in parallel
        results = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_index = {
                executor.submit(spam_killer._analyze_email_batch, email_with_index): email_with_index[0]
                for email_with_index in inbox_emails
            }
            
            completed_count = 0
            for future in as_completed(future_to_index):
                completed_count += 1
                scan_status.update({
                    'progress': completed_count,
                    'current_email': f'Analyzed {completed_count}/{len(inbox_emails)} emails'
                })
                
                try:
                    index, email, is_spam_result, reason = future.result()
                    results[index] = {
                        'email': email,
                        'is_spam': is_spam_result,
                        'reason': reason
                    }
                except Exception as e:
                    print(f"Error processing email: {e}")
        
        # Process results in order
        email_results = []
        for i in sorted(results.keys()):
            result = results[i]
            email = result['email']
            is_spam = result['is_spam']
            reason = result['reason']
            
            # Find unsubscribe links for spam emails
            unsubscribe_links = []
            if is_spam:
                try:
                    raw_html = spam_killer.get_raw_email_html(email['id'])
                    unsubscribe_links = spam_killer.find_unsubscribe_links(email['body'], raw_html)
                except Exception as e:
                    print(f"Error finding unsubscribe links: {e}")
            
            email_result = EmailResult(
                email_id=email['id'],
                subject=email['subject'][:80] + ('...' if len(email['subject']) > 80 else ''),
                sender=email['sender'],
                body_preview=email['body'][:200] + ('...' if len(email['body']) > 200 else ''),
                is_spam=is_spam,
                reason=reason,
                unsubscribe_links=unsubscribe_links[:3]  # Limit to first 3
            )
            email_results.append(email_result.dict())
        
        scan_status.update({
            'scanning': False,
            'current_email': 'Scan completed successfully!',
            'results': email_results
        })
        
    except Exception as e:
        scan_status.update({
            'scanning': False,
            'current_email': f'Error during scan: {str(e)}',
            'results': []
        })

@app.get("/api/results")
async def get_results():
    """Get scan results."""
    return {
        "results": scan_status['results'],
        "total": len(scan_status['results'])
    }

@app.post("/api/archive", response_model=ArchiveResponse)
async def archive_email(archive_request: ArchiveRequest):
    """Archive a spam email and optionally unsubscribe."""
    global spam_killer
    
    if spam_killer is None:
        raise HTTPException(status_code=400, detail="Not authenticated")
    
    try:
        # Try to unsubscribe first if requested
        unsubscribe_success = 0
        if archive_request.unsubscribe and archive_request.unsubscribe_links:
            unsubscribe_success = spam_killer.attempt_unsubscribe(archive_request.unsubscribe_links)
        
        # Archive the email
        if spam_killer.archive_email(archive_request.email_id):
            message = 'Email archived successfully!'
            if archive_request.unsubscribe and unsubscribe_success > 0:
                message += f' Unsubscribed from {unsubscribe_success} mailing lists.'
            elif archive_request.unsubscribe and unsubscribe_success == 0:
                message += ' (Unsubscribe attempts failed)'
            
            return ArchiveResponse(
                success=True,
                message=message,
                email_id=archive_request.email_id,
                unsubscribe_success=unsubscribe_success
            )
        else:
            return ArchiveResponse(
                success=False,
                message='Failed to archive email',
                email_id=archive_request.email_id
            )
            
    except Exception as e:
        return ArchiveResponse(
            success=False,
            message=f'Error: {str(e)}',
            email_id=archive_request.email_id
        )

if __name__ == '__main__':
    import uvicorn
    
    # Ensure templates directory exists
    os.makedirs('templates', exist_ok=True)
    
    print("🚀 Starting Gmail Spam Killer Web App...")
    print("🌐 Open your browser to http://localhost:8000")
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)