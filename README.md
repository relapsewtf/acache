# acache

Small toolkit to parse Windows ActivitiesCache DB for DFIR.

Usage:

```bash
python -m acache /path/to/activitiescache.db --exportjson out.json
```

Features added:
- Robust parsing with sqlite3.Row
- JSON payload parsing with error handling
- CSV and JSON export
- Simple timeline plotting
- Unit tests and GitHub Actions CI
