#!/usr/bin/env python3
"""
AI-powered Gmail spam filter that uses LLM to detect and archive spam emails.
This is a defensive security tool to help protect against unwanted emails.
"""

import base64
import json
import os
import pickle
import re
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

# Suppress XML parsed as HTML warning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import openai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Gmail API scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify'
]

USER_DESCRIPTION = "A 28 year old designer who lives in SF and NYC. His interests include gambling, clothes, cars."

MAX_EMAILS = 100
START_RANGE_DAYS = 14
END_RANGE_DAYS = 0
MAX_WORKERS = 40  # Number of parallel threads for OpenAI API calls

# Date range for email scanning (modify these to change the time window)
START_DATE = (datetime.now() - timedelta(days=START_RANGE_DAYS)).strftime('%Y/%m/%d')  # futher back
END_DATE = (datetime.now() - timedelta(days=END_RANGE_DAYS)).strftime('%Y/%m/%d')  # more recent

class GmailSpamKiller:
    def __init__(self):
        self.service = None
        # Initialize OpenAI client with minimal parameters to avoid conflicts
        import httpx
        self.openai_client = openai.OpenAI(
            api_key=os.getenv('OPENAI_API_KEY'),
            http_client=httpx.Client()
        )
        self.ai_archived_label_id = None
        self.spam_examples = []
        self.spam_detection_prompt_template = None
        
    def authenticate_gmail(self):
        """Authenticate with Gmail API using OAuth2."""
        creds = None
        
        # Token file stores user's access and refresh tokens
        if os.path.exists('token.json'):
            creds = Credentials.from_authorized_user_file('token.json', SCOPES)
            
        # If there are no valid credentials, let user log in
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                if not os.path.exists('credentials.json'):
                    print("Error: credentials.json file not found!")
                    print("Please download OAuth2 credentials from Google Cloud Console")
                    print("and save as 'credentials.json' in the project directory.")
                    return False
                    
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
                
            # Save credentials for next run
            with open('token.json', 'w') as token:
                token.write(creds.to_json())
                
        self.service = build('gmail', 'v1', credentials=creds)
        self._ensure_ai_archived_label()
        self._collect_spam_examples()
        return True
        
    def get_recent_emails(self, max_results=50):
        """Fetch emails from inbox within the specified date range."""
        try:
            # Build query with date range
            query = f'in:inbox after:{START_DATE} before:{END_DATE}'
            
            # Get list of messages
            results = self.service.users().messages().list(
                userId='me', 
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                # Get full message details
                msg = self.service.users().messages().get(
                    userId='me', 
                    id=message['id'],
                    format='full'
                ).execute()
                
                # Extract headers
                headers = msg['payload'].get('headers', [])
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                
                # Extract body
                body = self.extract_email_body(msg['payload'])
                
                emails.append({
                    'id': message['id'],
                    'subject': subject,
                    'sender': sender,
                    'body': body[:1000],  # Limit body length for API efficiency
                    'labels': msg.get('labelIds', [])
                })
                
            return emails
            
        except Exception as error:
            print(f'An error occurred: {error}')
            return []
            
    def extract_email_body(self, payload):
        """Extract clean, readable text content from email payload."""
        def decode_base64_data(data):
            """Safely decode base64 email data."""
            try:
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            except Exception:
                return ""
        
        def extract_text_from_parts(parts):
            """Recursively extract text from email parts."""
            text_content = ""
            html_content = ""
            
            for part in parts:
                mime_type = part.get('mimeType', '')
                
                # Handle nested parts (multipart)
                if 'parts' in part:
                    nested_text, nested_html = extract_text_from_parts(part['parts'])
                    text_content += nested_text
                    html_content += nested_html
                
                # Extract text/plain
                elif mime_type == 'text/plain' and 'data' in part.get('body', {}):
                    decoded = decode_base64_data(part['body']['data'])
                    text_content += decoded + "\n"
                
                # Extract text/html
                elif mime_type == 'text/html' and 'data' in part.get('body', {}):
                    decoded = decode_base64_data(part['body']['data'])
                    html_content += decoded + "\n"
            
            return text_content, html_content
        
        def clean_html_to_text(html_content):
            """Convert HTML to clean readable text."""
            try:
                soup = BeautifulSoup(html_content, 'lxml')
                
                # Remove script and style elements
                for script in soup(["script", "style", "meta", "link"]):
                    script.decompose()
                
                # Get text and clean it up
                text = soup.get_text()
                
                # Clean up whitespace
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                text = ' '.join(chunk for chunk in chunks if chunk)
                
                return text
            except Exception:
                return html_content  # Fallback to raw HTML if parsing fails
        
        def clean_text(text):
            """Clean and normalize text content."""
            if not text:
                return ""
            
            # Remove excessive whitespace
            text = re.sub(r'\s+', ' ', text)
            
            # Remove URLs that are just noise
            text = re.sub(r'https?://[^\s]+', '[URL]', text)
            
            # Remove email tracking pixels and long encoded strings
            text = re.sub(r'[a-zA-Z0-9+/]{50,}={0,2}', '[ENCODED_CONTENT]', text)
            
            # Remove excessive punctuation
            text = re.sub(r'[.]{3,}', '...', text)
            
            return text.strip()
        
        # Start extraction
        text_body = ""
        html_body = ""
        
        if 'parts' in payload:
            # Multipart email
            text_body, html_body = extract_text_from_parts(payload['parts'])
        else:
            # Single part email
            mime_type = payload.get('mimeType', '')
            if 'data' in payload.get('body', {}):
                decoded = decode_base64_data(payload['body']['data'])
                if mime_type == 'text/plain':
                    text_body = decoded
                elif mime_type == 'text/html':
                    html_body = decoded
        
        # Prefer plain text, but convert HTML if that's all we have
        if text_body:
            final_text = clean_text(text_body)
        elif html_body:
            final_text = clean_text(clean_html_to_text(html_body))
        else:
            final_text = ""
        
        # If we still don't have good content, try to extract from subject/headers
        if not final_text or len(final_text) < 20:
            final_text = "[Email body could not be extracted or is very short]"
        
        return final_text
        
    def is_spam(self, email):
        """Use LLM to determine if email is spam."""
        # Use the pre-built prompt template and fill in the email details
        prompt = self.spam_detection_prompt_template.format(
            subject=email['subject'],
            sender=email['sender'],
            body=email['body']
        )
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4.1",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100,
                temperature=0.1
            )
            
            result = response.choices[0].message.content.strip()
            return result.startswith("SPAM"), result
            
        except Exception as e:
            print(f"Error analyzing email: {e}")
            return False, "Error occurred"
    
    def _analyze_email_batch(self, email_with_index):
        """Analyze a single email and return result with original index."""
        index, email = email_with_index
        is_spam_result, reason = self.is_spam(email)
        return index, email, is_spam_result, reason
            
    def _ensure_ai_archived_label(self):
        """Create or find the 'AI Archived' label."""
        try:
            # Get all labels
            labels = self.service.users().labels().list(userId='me').execute()
            
            # Check if 'AI Archived' label exists
            for label in labels.get('labels', []):
                if label['name'] == 'AI Archived':
                    self.ai_archived_label_id = label['id']
                    return
            
            # Create the label if it doesn't exist
            label_object = {
                'name': 'AI Archived',
                'messageListVisibility': 'show',
                'labelListVisibility': 'labelShow'
            }
            
            created_label = self.service.users().labels().create(
                userId='me',
                body=label_object
            ).execute()
            
            self.ai_archived_label_id = created_label['id']
            print(f"Created 'AI Archived' label with ID: {self.ai_archived_label_id}")
            
        except Exception as e:
            print(f"Error creating/finding AI Archived label: {e}")
            self.ai_archived_label_id = None
    
    def _collect_spam_examples(self):
        """Collect examples from the user's spam folder to improve detection."""
        try:
            print("📚 Collecting spam examples from your spam folder...")
            
            # Query for spam emails
            results = self.service.users().messages().list(
                userId='me',
                labelIds=['SPAM'],
                maxResults=10  # Get up to 10 examples
            ).execute()
            
            messages = results.get('messages', [])
            
            for message in messages:
                try:
                    # Get message details
                    msg = self.service.users().messages().get(
                        userId='me',
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    # Extract headers
                    headers = msg['payload'].get('headers', [])
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                    
                    # Extract body (limited)
                    body = self.extract_email_body(msg['payload'])
                    
                    self.spam_examples.append({
                        'subject': subject[:100],  # Limit length
                        'sender': sender[:100],
                        'body': body[:1000]  # Limit body length
                    })
                    
                except Exception as e:
                    print(f"Error processing spam example: {e}")
                    continue
            
            print(f"✅ Collected {len(self.spam_examples)} spam examples for improved detection")
            
        except Exception as e:
            print(f"⚠️  Could not collect spam examples: {e}")
            self.spam_examples = []
        
        # Build the prompt template once
        self._build_spam_detection_prompt()

        # Remove debug output of prompt
        # print("The prompt is ============================")
        # print(self.spam_detection_prompt_template)
    
    def _build_spam_detection_prompt(self):
        """Build the spam detection prompt template once with collected examples."""
        # Build spam examples section
        spam_examples_text = ""
        if self.spam_examples:
            spam_examples_text = "\n\nHere are examples of emails that were previously identified as spam:\n"
            for i, example in enumerate(self.spam_examples[:5], 1):  # Use up to 5 examples
                spam_examples_text += f"\nSpam Example {i}:\n"
                spam_examples_text += f"Subject: {example['subject']}\n"
                spam_examples_text += f"From: {example['sender']}\n"
                spam_examples_text += f"Body: {example['body']}\n"
        
        self.spam_detection_prompt_template = f"""
You are analyzing the inbox of {USER_DESCRIPTION}.

Analyze this email and determine if it's spam. Consider factors like:
- Unsolicited promotional content
- Domestic violence related
- Foreign languages
- Religious content
- Similarity to known spam patterns: {spam_examples_text}

===================================================================
Email to Analyze:
Subject: {{subject}}
From: {{sender}}
Body: {{body}}

Based on the above criteria and spam examples, respond with only "SPAM" or "NOT_SPAM" followed by a brief reason.
"""
    
    def archive_email(self, email_id):
        """Archive an email by removing INBOX label and adding AI Archived label."""
        try:
            body = {'removeLabelIds': ['INBOX']}
            
            # Add AI Archived label if available
            if self.ai_archived_label_id:
                body['addLabelIds'] = [self.ai_archived_label_id]
            
            self.service.users().messages().modify(
                userId='me',
                id=email_id,
                body=body
            ).execute()
            return True
        except Exception as e:
            print(f"Error archiving email {email_id}: {e}")
            return False
            
    def run_spam_filter(self, dry_run=True, max_emails=MAX_EMAILS):
        """Main function to run the spam filter with parallelized analysis."""
        start_time = time.time()
        
        print("🛡️  AI Gmail Spam Killer - Defensive Email Security Tool")
        print("=" * 60)
        
        if not self.authenticate_gmail():
            return
            
        if self.ai_archived_label_id:
            print(f"✅ 'AI Archived' label ready (ID: {self.ai_archived_label_id})")
        else:
            print("⚠️  Warning: Could not create/find 'AI Archived' label")
            
        print(f"Fetching up to {max_emails} emails from {START_DATE} to {END_DATE}...")
        emails = self.get_recent_emails(max_emails)
        
        if not emails:
            print("No emails found.")
            return
        
        # Filter emails to only process those in INBOX
        inbox_emails = [(i, email) for i, email in enumerate(emails) if 'INBOX' in email['labels']]
        
        if not inbox_emails:
            print("No emails in inbox to process.")
            return
        
        analysis_start_time = time.time()
        print(f"📊 Analyzing {len(inbox_emails)} emails in parallel using {MAX_WORKERS} workers...")
        
        # Store results with original index to maintain order
        results = {}
        spam_count = 0
        
        # Process emails in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all analysis tasks
            future_to_index = {executor.submit(self._analyze_email_batch, email_with_index): email_with_index[0] 
                              for email_with_index in inbox_emails}
            
            # Collect results as they complete
            completed_count = 0
            for future in as_completed(future_to_index):
                completed_count += 1
                print(f"\r⚡ Progress: {completed_count}/{len(inbox_emails)} emails analyzed", end="", flush=True)
                
                try:
                    index, email, is_spam_result, reason = future.result()
                    results[index] = {
                        'email': email,
                        'is_spam': is_spam_result,
                        'reason': reason
                    }
                    if is_spam_result:
                        spam_count += 1
                except Exception as e:
                    print(f"\nError processing email: {e}")
        
        analysis_end_time = time.time()
        analysis_time = analysis_end_time - analysis_start_time
        
        print(f"\n⚡ Analysis completed in {analysis_time:.2f} seconds")
        print("=" * 60)
        print("📋 Analysis Results (in original order):")
        print("=" * 60)
        
        # Display results in original order
        for i in sorted(results.keys()):
            result = results[i]
            email = result['email']
            is_spam_result = result['is_spam']
            reason = result['reason']
            
            print(f"\n📧 Processing: {email['subject'][:50]}...")
            print(f"   From: {email['sender']}")
            
            if is_spam_result:
                print(f"   🚨 SPAM DETECTED: {reason}")
                
                if dry_run:
                    print("   [DRY RUN] Would archive and label as 'AI Archived'")
                else:
                    if input("   Archive this email? (y/N): ").lower() == 'y':
                        if self.archive_email(email['id']):
                            print("   ✅ Email archived and labeled as 'AI Archived'")
                        else:
                            print("   ❌ Failed to archive email")
                    else:
                        print("   ⏭️  Skipped")
            else:
                print(f"   ✅ Clean: {reason}")
                
        end_time = time.time()
        total_time = end_time - start_time
        
        print(f"\n📊 Summary:")
        print(f"   Processed: {len(inbox_emails)} emails")
        print(f"   Spam detected: {spam_count} emails")
        print(f"   Mode: {'DRY RUN' if dry_run else 'LIVE'}")
        print(f"   Parallelization: {MAX_WORKERS} workers")
        print(f"   ⏱️  Total execution time: {total_time:.2f} seconds")
        if len(inbox_emails) > 0:
            print(f"   ⚡ Average time per email: {total_time/len(inbox_emails):.2f} seconds")

def main():
    """Main entry point."""
    script_start_time = time.time()
    
    if not os.getenv('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY environment variable not set!")
        print("Please create a .env file with your OpenAI API key:")
        print("OPENAI_API_KEY=your_api_key_here")
        return
        
    spam_killer = GmailSpamKiller()
    
    # Run in dry-run mode by default for safety
    print("Running in DRY RUN mode (no emails will be archived)")
    print("To run live mode, edit the script and set dry_run=False")
    spam_killer.run_spam_filter(dry_run=True, max_emails=MAX_EMAILS)
    
    script_end_time = time.time()
    total_script_time = script_end_time - script_start_time
    print(f"\n🏁 Script completed in {total_script_time:.2f} seconds total")

if __name__ == "__main__":
    main()