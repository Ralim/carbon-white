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
3. Select a file to upload (up to 200MB)
4. Click "Submit Document"

### Downloading Documents

- Click the "Download" button next to any search result
- Files are served with original filenames

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
docker run -d -p 8080:8080 \
  -e CARBON_DATA_DIR=/data \  # Directory inside the container to store files
  -e CARBON_AUTH_KEY=your-secret-auth-key \  # Set your auth key
  --volume /path/to/local/data:/data \  # Map local data directory
  --name carbon-white \
  ghcr.io/ralim/carbon-white:main
```

### Locally

#### Environment Variables

When running, the project requires 3 env variables to set for correct performance.

```env
CARBON_DATA_DIR=/path/to/data/directory
CARBON_AUTH_KEY=your-secret-auth-key
CARBON_WHITELIST_IPS=127.0.0.1,::1,192.168.1.100
RECENT_FILE_COUNT=10
```

- `CARBON_DATA_DIR`: Directory where files and database will be stored (defaults to `/tmp/carbon/`)
- `CARBON_AUTH_KEY`: Secret key for authentication (required for production)
- `CARBON_WHITELIST_IPS`: Comma-separated list of allowed IP addresses (empty = allow all) for login
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
