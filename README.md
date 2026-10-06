# self_osint_tool

`self_osint.py` is a command-line self-OSINT audit tool. It checks your own
usernames, email addresses, name, and local images by running available
third-party tools, then combines their results into a Markdown report and a
CSV findings log.

Use it only with identifiers and data that you own or are authorized to
investigate. External services have their own rate limits and terms of use.

## How it works

The script does not implement every OSINT service itself. Instead, it:

1. Validates that at least one identifier was provided.
2. Checks whether each optional tool is available on `PATH`.
3. Runs only the scans enabled by the supplied inputs:
   - usernames run Sherlock and Maigret;
   - emails run Holehe and the HIBP API check;
   - images run ExifTool;
   - `--spiderfoot` enables SpiderFoot for the supplied name, usernames, and
     email addresses.
4. Captures each tool's standard output and errors in `raw/`.
5. Parses tool output into a common finding format.
6. Deduplicates identical findings across tools. Matching is case-insensitive
   and uses the identifier, source, detail, and category. When multiple tools
   report the same finding, the `tool` field lists all of them and the highest
   risk level is retained.
7. Writes `report.md` and `findings.csv`.
8. Prints skipped tools and their reasons instead of failing the entire scan.

Unavailable tools are skipped. For example, a missing tool is reported as
`skipped: not installed`, while HIBP is reported as
`skipped: no API key` when no key is configured.

## Tools and scan types

| Tool | Input | Purpose | Installation |
|---|---|---|---|
| Sherlock | Usernames | Finds username accounts | `requirements.txt` |
| Maigret | Usernames | Finds username accounts | `requirements.txt` |
| Holehe | Emails | Checks sites where an email is registered | `requirements.txt` |
| HIBP API v3 | Emails | Checks known breach records | API key required |
| ExifTool | Images | Reads GPS, device, author, serial, and date metadata | System package |
| SpiderFoot | Name, usernames, emails | Optional passive correlation | Separate checkout |

## Installation

### Python environment

Create and activate the repository-local virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate it with:

```powershell
.venv\Scripts\Activate.ps1
```

The virtual environment keeps the OSINT packages separate from your system
Python. The repository's `.gitignore` excludes `.venv/`, Python caches, and
generated audit output.

### ExifTool

ExifTool is a system executable, not a Python package:

```bash
# macOS
brew install exiftool

# Debian/Ubuntu
sudo apt install libimage-exiftool-perl
```

### SpiderFoot

SpiderFoot is a standalone application and is not installed by
`requirements.txt`:

```bash
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
python3 sf.py -l 127.0.0.1:5001
```

When using `--spiderfoot`, `sf.py` must be available on `PATH`. SpiderFoot
may require a compatible Python version and its own dependency installation.
On Python 3.14, some SpiderFoot dependencies may fail to build, especially
older `lxml` releases. This does not prevent the other scans from running.

### HIBP

HIBP requires an API key. Set it in the environment:

```bash
export HIBP_API_KEY="your-api-key"
```

Or provide it for one run:

```bash
python self_osint.py -e me@example.com --hibp-key "your-api-key"
```

The key is not written to the report or CSV. HIBP requests are rate-limited,
so scans with multiple email addresses may take several seconds between
requests.

## Usage

Run a scan with a name, username, email addresses, and images:

```bash
python self_osint.py \
  --name "First Last" \
  -u handle1 \
  -u oldhandle \
  -e me@example.com \
  -e old@example.com \
  -i ./my_photos
```

The options are:

| Option | Description |
|---|---|
| `--name NAME` | Full name to include in manual searches and SpiderFoot |
| `-u`, `--username USERNAME` | Username; repeat for multiple usernames |
| `-e`, `--email EMAIL` | Email address; repeat for multiple emails |
| `-i`, `--images PATH` | Image file or directory; repeat as needed |
| `--hibp-key KEY` | HIBP API key; otherwise `HIBP_API_KEY` is used |
| `--spiderfoot` | Enable the optional SpiderFoot scan |
| `--timeout SECONDS` | Timeout for normal external commands; default `600` |
| `--sf-timeout SECONDS` | SpiderFoot timeout per target; default `1800` |
| `-o`, `--out DIRECTORY` | Output directory; default `osint_audit` |

At least one of `--name`, `--username`, `--email`, or `--images` is required.

## Output and repeated runs

By default, every run uses the same directory:

```text
osint_audit/
├── findings.csv
├── report.md
└── raw/
```

Running the project repeatedly does not create a new timestamped folder each
time. The latest run replaces `report.md` and `findings.csv`, and the
tool-generated `raw/` directory is deleted and recreated at the start of
each run. This prevents stale logs from being mistaken for results from the
current scan.

Use `--out` to preserve a scan under a separate name:

```bash
python self_osint.py \
  --name "First Last" \
  -u handle1 \
  -o scans/first-last-2026-10-06
```

The `raw/` directory is expected to be empty when no external tool produced
output. Check the report's **Tool status** table to see whether a tool was
missing, skipped because of missing input, or ran successfully.

## `report.md`

The Markdown report contains:

- scan start and completion timestamps;
- total scan duration;
- Python version;
- total findings after deduplication;
- the identifiers searched;
- each tool's status and finding count;
- high-risk findings;
- findings grouped by scan type;
- manual Google search follow-ups;
- reverse-image-search suggestions;
- data-broker follow-ups;
- the location of raw tool output.

Risk levels are:

- `H`: high risk;
- `M`: medium risk;
- `L`: low risk;
- `?`: uncertain or unclassified.

The report is an automated starting point. Findings should be manually
verified before taking action.

## `findings.csv`

The CSV contains one row for each unique finding after cross-tool
deduplication. Its columns are:

| Column | Meaning |
|---|---|
| `tool` | Tool or comma-separated tools that reported the finding |
| `identifier` | Username, email, image, or other searched identifier |
| `source` | Website, module, file, or other source |
| `detail` | Parsed finding details |
| `category` | Finding type, such as `Old account`, `Location`, or `Images` |
| `risk` | `H`, `M`, `L`, or `?` |
| `action` | Suggested next step based on category and risk |
| `status` | Starts as `open` for manual review |
| `scan_started` | Scan start timestamp |
| `scan_completed` | Scan completion timestamp |

The file is always created with a header, even when no findings are found.
Examples of recommended actions include closing unused accounts, changing
affected passwords, enabling MFA, and removing GPS metadata from images.

## Testing and troubleshooting

Activate the environment and run the basic checks:

```bash
source .venv/bin/activate
python -m py_compile self_osint.py
python -m pip check
python self_osint.py --help
```

Check which external tools are available:

```bash
command -v sherlock maigret holehe spiderfoot exiftool
```

If the report has zero findings:

1. Read the **Tool status** table.
2. Confirm the relevant tools are installed and available on `PATH`.
3. Confirm the matching input was supplied, such as `-u` for usernames or
   `-i` for images.
4. Configure `HIBP_API_KEY` if breach checks are needed.
5. Inspect `osint_audit/raw/` for the exact output and errors from tools that
   did run.

An empty `raw/` directory is not itself an error. It means that no tool
produced a raw output file during that run.

## Privacy and safety

Reports and raw logs may contain sensitive personal information. Keep
`osint_audit/` private, do not commit it to source control, and remove or
secure old reports when they are no longer needed. The generated output is
ignored by Git in this repository.

Google dorks and data brokers are listed as manual follow-ups. The tool does
not scrape search engines or broker sites because that can trigger CAPTCHAs
and violate their terms of use.
