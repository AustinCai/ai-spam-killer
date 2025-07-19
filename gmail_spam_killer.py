#!/usr/bin/env python3
"""
AI-powered Gmail spam filter that uses LLM to detect and archive spam emails.
This is a defensive security tool to help protect against unwanted emails.
"""

import base64
import json
import os
import pickle
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from pathlib import Path

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

MAX_EMAILS = 100
START_RANGE_DAYS = 14
END_RANGE_DAYS = 0

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
        """Extract text content from email payload."""
        body = ""
        
        if 'parts' in payload:
            for part in payload['parts']:
                if part['mimeType'] == 'text/plain':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
                    break
                elif part['mimeType'] == 'text/html':
                    data = part['body']['data']
                    body = base64.urlsafe_b64decode(data).decode('utf-8')
        else:
            if payload['mimeType'] == 'text/plain':
                data = payload['body']['data']
                body = base64.urlsafe_b64decode(data).decode('utf-8')
                
        return body
        
    def is_spam(self, email):
        """Use LLM to determine if email is spam."""
        prompt = f"""
        Analyze this email and determine if it's spam. Consider factors like:
        - Suspicious sender addresses
        - Phishing attempts
        - Unsolicited promotional content
        - Scam indicators
        - Poor grammar/suspicious language
        - Requests for personal information
        
        Email Details:
        Subject: {email['subject']}
        From: {email['sender']}
        Body: {email['body']}
        
        Respond with only "SPAM" or "NOT_SPAM" followed by a brief reason.
        """
        
        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=100,
                temperature=0.1
            )
            
            result = response.choices[0].message.content.strip()
            return result.startswith("SPAM"), result
            
        except Exception as e:
            print(f"Error analyzing email: {e}")
            return False, "Error occurred"
            
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
        """Main function to run the spam filter."""
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
            
        spam_count = 0
        processed_count = 0
        
        for email in emails:
            # Skip already archived emails
            if 'INBOX' not in email['labels']:
                continue
                
            processed_count += 1
            print(f"\n📧 Processing: {email['subject'][:50]}...")
            print(f"   From: {email['sender']}")
            
            is_spam_result, reason = self.is_spam(email)
            
            if is_spam_result:
                spam_count += 1
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
                
        print(f"\n📊 Summary:")
        print(f"   Processed: {processed_count} emails")
        print(f"   Spam detected: {spam_count} emails")
        print(f"   Mode: {'DRY RUN' if dry_run else 'LIVE'}")

def main():
    """Main entry point."""
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

if __name__ == "__main__":
    main()