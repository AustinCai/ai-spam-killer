# AI Gmail Spam Killer

A defensive security tool that uses AI to automatically detect and archive spam emails in Gmail.

## Features

- 🛡️ **Defensive Security**: Protects against spam and phishing attempts
- 🤖 **AI-Powered**: Uses OpenAI GPT to intelligently detect spam patterns
- 🔒 **Safe by Default**: Runs in dry-run mode to preview actions
- 📧 **Gmail Integration**: Works directly with Gmail API
- ⚡ **Manual Execution**: Run on-demand rather than continuously

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Set up Gmail API Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Gmail API
4. Create OAuth 2.0 credentials (Desktop Application)
5. Download the credentials file as `credentials.json` in this directory

### 3. Set up OpenAI API Key

1. Copy `.env.example` to `.env`
2. Add your OpenAI API key to the `.env` file

```bash
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

## Usage

### First Run (Authentication)

```bash
python gmail_spam_killer.py
```

This will:
- Open a browser for Gmail OAuth authentication
- Save authentication tokens for future use
- Run in dry-run mode to show what would be archived

### Dry Run Mode (Safe Preview)

By default, the script runs in dry-run mode and won't actually archive emails:

```bash
python gmail_spam_killer.py
```

### Live Mode (Actually Archive Spam)

To enable actual archiving, edit `gmail_spam_killer.py` and change:

```python
spam_killer.run_spam_filter(dry_run=False, max_emails=20)
```

## How It Works

1. **Fetch Recent Emails**: Retrieves up to 20 recent emails from your inbox
2. **AI Analysis**: Sends email content to OpenAI GPT for spam detection
3. **Spam Detection**: Analyzes subject, sender, and body for spam indicators
4. **Safe Archiving**: Archives detected spam (removes from inbox)
5. **User Control**: Asks for confirmation before archiving in live mode

## Safety Features

- **Dry-run by default**: Never archives emails unless explicitly enabled
- **User confirmation**: Prompts before archiving each spam email in live mode
- **Limited scope**: Only processes recent emails (configurable)
- **Defensive only**: Designed to protect, not attack

## Security Considerations

- OAuth tokens are stored locally in `token.json`
- OpenAI API key should be kept secure in `.env` file
- Script only reads and modifies your own Gmail account
- No data is stored permanently except for authentication tokens

## Troubleshooting

- Ensure `credentials.json` is in the project directory
- Check that Gmail API is enabled in Google Cloud Console
- Verify OpenAI API key is valid and has sufficient credits
- For authentication issues, delete `token.json` and re-authenticate