# Carbon White

A web tool for storing and retrieving documentation and datasheets built with Rust and Leptos.
This is really just designed to make me happy managing an ever growing documentation hub and folders that are getting chunky.
The _intent_ is that this can be self hosted at home or a workplace easily, then used as a place to dump datasheets and reference material.

## Features

- **File storage** Once submitted, files are stored on disk; nice and simple
- **Deduplication** Files are stored by their SHA256 hash, so duplicates are automatically handled, resubmitting just updates a file
- **Metadata** Each document can have metadata like title, part number, manufacturer, version, etc.
- **Search** Full text search across all metadata fields

## Usage

### Authentication

1. Navigate to the login page (`/login`) or the button in the top right
2. Enter the authentication key configured in `CARBON_AUTH_KEY`
3. Upon successful authentication, you'll be redirected to the search page, and can see the submit button now

Sessions last 24 hours. They are signed with a random key generated when the server starts, so restarting the server logs everyone out.

After 3 failed login attempts a client address (or IPv6 /64) is blocked from logging in for 24 hours. Bans are held in memory only and are cleared when the server restarts.

### Searching Documents

- Use the main search box to find documents
- Search across titles, part numbers, manufacturers, and other metadata

### Submitting Documents

1. Click "Submit" in the header (requires authentication)
2. Fill in the document metadata:
   - **Title** (required)
   - Part Number
   - Manufacturer
   - Document ID
   - Document Version
   - Package Marking
   - Device Address
   - Notes
3. Select a file to upload (up to 250 MiB)
4. Click "Submit Document"

### Downloading Documents

- Click the "Download" button next to any search result
- Files are served with original filenames
- PDFs, raster images and plain text open in the browser; every other type (including HTML and SVG) is downloaded rather than rendered

## Developing

### Installation

1. Install `cargo-leptos`:

```sh
cargo install cargo-leptos
```

2. Clone the repository:

```sh
git clone <repository-url>
cd carbon-white
```

## Running the Application

### Container

This repo is published to `ghcr.io/ralim/carbon-white:main`
You can run it with:

```sh
podman run -d -p 8080:8080 \
  -e CARBON_AUTH_KEY=your-secret-auth-key \
  --userns=keep-id:uid=10001,gid=10001 \
  --volume /path/to/local/data:/data:Z \
  --name carbon-white \
  ghcr.io/ralim/carbon-white:main
```

- `CARBON_DATA_DIR` defaults to `/data` inside the image; mount your data directory there.
- The server runs as the unprivileged user `10001:10001`, so the mounted directory must be writable by that ID. With rootless podman, `--userns=keep-id:uid=10001,gid=10001` maps it to your own user. Otherwise run `chown -R 10001:10001 /path/to/local/data` once (images before this change ran as root, so existing data directories need this).

### Locally

#### Environment Variables

When running, the project requires 3 env variables to set for correct performance.

```env
CARBON_DATA_DIR=/path/to/data/directory
CARBON_AUTH_KEY=your-secret-auth-key
CARBON_WHITELIST_IPS=127.0.0.1,::1,192.168.1.100,192.168.0.0/24
CARBON_TRUSTED_PROXIES=10.0.0.1
RECENT_FILE_COUNT=10
```

- `CARBON_DATA_DIR`: Directory where files and database will be stored (defaults to `/tmp/carbon/`, which many systems clear on reboot, so set this for any real use)
- `CARBON_AUTH_KEY`: Secret key for authentication (required for production)
- `CARBON_WHITELIST_IPS`: Comma-separated list of IP addresses or subnets allowed to log in. Defaults to `127.0.0.1,::1`; if it is empty or holds no valid entries, only loopback clients may log in. Invalid entries are logged and skipped
- `CARBON_TRUSTED_PROXIES`: Comma-separated list of reverse proxy addresses or subnets. `X-Forwarded-For` / `X-Real-IP` are only honoured on connections from these peers (empty = headers ignored, the socket address is used)
- `RECENT_FILE_COUNT`: Number of recent files to show on the homepage (default 10)

#### Running in Development

```bash
cargo leptos watch
```

This will:

- Start the development server on `http://localhost:3000`
- Watch for file changes and auto-reload
- Compile both frontend and backend

#### Building for Production

```bash
cargo leptos build --release
```

#### Running Tests

```bash
cargo test
```
