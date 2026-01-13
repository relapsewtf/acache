# acache

Small, single-file toolkit to parse Windows ActivitiesCache DB for DFIR .

Usage:

```bash
python3 acache.py /path/to/activitiescache.db --exportjson out.json
```

File scanning for suspicious files (basic):

```bash
python3 acache.py /path/to/activitiescache.db --filescan /path/to/scan --filescan-recursive --exportjson out.json
```

New features and improvements:
- Robust parsing with sqlite3.Row
- Streaming JSON parsing (low memory) and improved JSON data modeling
- CSV and JSON export (optional pandas CSV support with `--use-pandas`)
- Simple timeline plotting with matplotlib dates
- Unit tests and GitHub Actions CI
- Inlined file scanning functionality (formerly `file_analyzer.py`) with filters and a 0-100 maliciousness score
- CLI improvements: `--verbose` for debug logging, `--use-pandas` for CSV exports, console script `activitiescache`
- Animated ASCII banner shown by default while analysis runs; disable with `ACACHE_NO_ANIMATION=1` (non-TTYs skip animation automatically)

Notes & caveats:
- Windows-specific checks (registry Run keys, scheduled tasks, detailed signature validation, USN checks) only run on Windows.
- VirusTotal lookups require a VT API key (export `VT_API_KEY` or pass `--vt-key`).
- Scoring is heuristic; tune `WEIGHTS` in `acache.py` to adjust sensitivity.

Installation & usage:

Install editable for development:

```bash
python -m pip install -e .
```

After install, run with the console script:

```bash
activitiescache /path/to/activitiescache.db --exportjson out.json --verbose
```

Or run the script directly:

```bash
python3 acache.py /path/to/activitiescache.db --exportcsv out.csv --use-pandas
```

## report & autosave

The tool generates an interactive HTML report (dark-blue theme) saved next to the DB as `<basename>.report.html`, along with `<basename>.parsed.json` and `<basename>.insights.json`.

### examples

Save parsed data + HTML report:

```bash
python -m acache /path/to/activitiescache.db --exportjson out.json
# files created next to DB: activitiescache.parsed.json, activitiescache.insights.json, activitiescache.report.html
```

Scan a folder recursively and append filescan results:

```bash
python -m acache /path/to/activitiescache.db --filescan /path/to/suspect --filescan-recursive --vt-key YOUR_KEY
```

---

made by relapse & git copilot

# this text was FULLY made by copilot summarizing my text
