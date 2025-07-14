# Slack OAuth2 Platform Adapter

This adapter provides a pluggable implementation for integrating Slack as a messaging platform. It is designed to work with [RelaySMS Publisher](https://github.com/smswithoutborders/RelaySMS-Publisher), enabling users to connect to Slack using OAuth2 authentication.

## Requirements

- **Python**: Version >=
  [3.8.10](https://www.python.org/downloads/release/python-3810/)
- **Python Virtual Environments**:
  [Documentation](https://docs.python.org/3/tutorial/venv.html)

## Dependencies

### On Ubuntu

Install the necessary system packages:

```bash
sudo apt install build-essential python3-dev
```

## Installation

1. **Create a virtual environment:**

   ```bash
   python3 -m venv venv
   ```

2. **Activate the virtual environment:**

   ```bash
   . venv/bin/activate
   ```

3. **Install the required Python packages:**

   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Step 1: Create and Configure Your Slack App

1. **Create a new Slack app:**

   - Go to the [Slack API Apps page](https://api.slack.com/apps)
   - Click **"Create New App"**
   - Choose **"From scratch"**
   - Enter your app name and select the workspace where you want to develop the app
   - Click **"Create App"**

2. **Configure OAuth & Permissions:**

   - In your app's settings, navigate to **"OAuth & Permissions"** in the left sidebar
   - Scroll down to **"Redirect URLs"** section
   - Click **"Add New Redirect URL"**
   - Add your redirect URI (e.g., `https://example.com/callback/`)
   - Click **"Save URLs"**

3. **Enable Token Rotation:**

   - In the same **"OAuth & Permissions"** page, scroll down to **"Token Rotation"** section
   - Click **"Opt into Token Rotation"**
   - This ensures that a refresh token is returned every time a user grants access to your app
   - Click **"Save Changes"**

4. **Set up User Token Scopes:**

   - In the same **"OAuth & Permissions"** page, scroll down to **"Scopes"**
   - Under **"User Token Scopes"**, click **"Add an OAuth Scope"**
   - Add the following required scopes:
     - `chat:write`
     - `profile`
     - `users:read`
     - `users:read.email`
   - Click **"Save Changes"**

5. **Enable public distribution (optional):**

   - To allow your app to work with different workspaces, go to **"Manage Distribution"** in the left sidebar
   - Under **"Share Your App with Other Workspaces"**, review the checklist requirements
   - Once all requirements are met, click **"Activate Public Distribution"**
   - This makes your app available for installation in any workspace

6. **Gather your app credentials:**
   - Go to **"Basic Information"** in the left sidebar
   - Under **"App Credentials"**, you'll find:
     - **Client ID** - Copy this value
     - **Client Secret** - Click "Show" and copy this value

### Step 2: Create Your Credentials File

Create a `credentials.json` file with your Slack app information obtained from Step 1 point 5:

**Sample `credentials.json`**

```json
{
  "client_id": "your_client_id_here",
  "client_secret": "your_client_secret_here",
  "redirect_uris": ["https://example.com/callback/"]
}
```

**Field descriptions:**

- `client_id`: Your app's Client ID from the Basic Information page
- `client_secret`: Your app's Client Secret from the Basic Information page
- `redirect_uris`: Array of redirect URLs you configured in OAuth & Permissions (must match exactly)

> [!TIP]
>
> **Local Development with HTTPS:**
>
> OAuth2 authorization servers require HTTPS protocol for redirect URIs. For local development, you can use these tools to create secure tunnels:
>
> - **[ngrok](https://ngrok.com/)**: `ngrok http 3000` (expose localhost:3000 via HTTPS)
> - **[localtunnel](https://github.com/localtunnel/localtunnel)**: `lt --port 3000` (npm package)
> - **[VS Code Tunnels](https://code.visualstudio.com/docs/remote/tunnels)**: Built into VS Code for port forwarding
> - **[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)**: Free secure tunnels to localhost

### Step 3: Configure the Credentials File Path

Create or edit your `config.ini` file to specify the path to your credentials:

```ini
[credentials]
path = ./credentials.json
```

## Using the CLI

> [!NOTE]
>
> Use the `--help` flag with any command to see the available parameters and their descriptions.

### 1. **Generate Authorization URL**

Use the `auth-url` command to generate the OAuth2 authorization URL.

```bash
python3 slack_cli.py auth-url -o session.json
```

- `-o`: Save the output to `session.json`.

### 2. **Exchange Authorization Code**

Use the `exchange` command to exchange the authorization code for tokens and user info.

```bash
python3 slack_cli.py exchange -c auth_code -o session.json -f session.json
```

- `-c`: Authorization code.
- `-o`: Save the output to `session.json`.
- `-f`: Read parameters from `session.json`.

### 3. **Send a Message**

Use the `send-message` command to send a message using the adapter.

```bash
python3 slack_cli.py send-message -f session.json -m "Hello, Slack!" -r "social" -o session.json
```

- `-f`: Read parameters from `session.json`.
- `-m`: Message to send.
- `-r`: Recipient channel or user ID.
- `-o`: Save the output to `session.json`.

### 4. **Revoke Token**

Use the `revoke` command to revoke the OAuth2 token and invalidate the user's session.

```bash
python3 slack_cli.py revoke -f session.json -o session.json
```

- `-f`: Read token from `session.json`.
- `-o`: Update the file by removing the revoked token.

> [!WARNING]
>
> After revoking a token, the user will need to re-authenticate to use the adapter again. The revoked token will be removed from the output file if specified.

## TODO

- Add support for direct message sending to specific users
- Implement message formatting options (markdown, attachments, etc.)
- Add support for channel listing and user discovery
