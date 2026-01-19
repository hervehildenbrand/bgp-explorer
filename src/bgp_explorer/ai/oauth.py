"""OAuth credential management for Google Gemini API."""

import os
from pathlib import Path
from typing import Optional

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Scopes required for Gemini API access
SCOPES = ["https://www.googleapis.com/auth/generative-language.retriever"]

# Default paths for credential files
DEFAULT_CLIENT_SECRET = "client_secret.json"
DEFAULT_TOKEN_CACHE = ".bgp_explorer_token.json"


def get_oauth_credentials(
    client_secret_path: Optional[str] = None,
    token_cache_path: Optional[str] = None,
) -> Credentials:
    """Load or create OAuth credentials for Gemini API.

    On first run, opens a browser for Google login. Subsequent runs
    use cached credentials from the token file.

    Args:
        client_secret_path: Path to client_secret.json from Google Cloud Console.
                           Defaults to ./client_secret.json or ~/.config/bgp-explorer/client_secret.json
        token_cache_path: Path to cache the OAuth token.
                         Defaults to ~/.config/bgp-explorer/.bgp_explorer_token.json

    Returns:
        Valid OAuth credentials for Gemini API.

    Raises:
        FileNotFoundError: If client_secret.json is not found.
        ValueError: If OAuth flow fails.
    """
    # Determine paths
    config_dir = Path.home() / ".config" / "bgp-explorer"

    # Find client secret file
    if client_secret_path:
        secret_path = Path(client_secret_path)
    elif Path(DEFAULT_CLIENT_SECRET).exists():
        secret_path = Path(DEFAULT_CLIENT_SECRET)
    elif (config_dir / DEFAULT_CLIENT_SECRET).exists():
        secret_path = config_dir / DEFAULT_CLIENT_SECRET
    else:
        raise FileNotFoundError(
            f"OAuth client_secret.json not found. Please either:\n"
            f"  1. Place it in current directory: ./{DEFAULT_CLIENT_SECRET}\n"
            f"  2. Place it in config directory: {config_dir / DEFAULT_CLIENT_SECRET}\n"
            f"  3. Specify path with --client-secret option\n\n"
            f"To create client_secret.json:\n"
            f"  1. Go to https://console.cloud.google.com/apis/credentials\n"
            f"  2. Create OAuth 2.0 Client ID (Desktop app)\n"
            f"  3. Download the JSON file and rename to client_secret.json"
        )

    # Determine token cache path
    if token_cache_path:
        token_path = Path(token_cache_path)
    else:
        config_dir.mkdir(parents=True, exist_ok=True)
        token_path = config_dir / DEFAULT_TOKEN_CACHE

    # Load existing credentials if available
    creds = None
    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
        except Exception:
            # Invalid token file, will re-authenticate
            pass

    # Refresh or create new credentials
    if creds and creds.valid:
        return creds

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            # Save refreshed token
            token_path.write_text(creds.to_json())
            return creds
        except Exception:
            # Refresh failed, need to re-authenticate
            pass

    # Need new authentication - run OAuth flow
    flow = InstalledAppFlow.from_client_secrets_file(str(secret_path), SCOPES)
    creds = flow.run_local_server(port=0)

    # Cache the credentials
    token_path.write_text(creds.to_json())

    return creds
