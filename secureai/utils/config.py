import os
import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv

# Load local .env (The file you correctly gitignored)
load_dotenv()

def get_config(key_name, default=None):
    """Bridge Phase 4 (AWS) and Phase 5 (Local/Detection)."""
    try:
        ssm = boto3.client('ssm', region_name='us-east-1')
        return ssm.get_parameter(Name=f"/secureai/{key_name.lower()}", WithDecryption=True)['Parameter']['Value']
    except (BotoCoreError, ClientError, Exception):
        # Fallback to the .env template we just verified
        return os.getenv(key_name.upper(), default)

# Global settings for the platform
ANTHROPIC_API_KEY = get_config("anthropic_key", "dev_fallback")
