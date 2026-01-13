#!/usr/bin/env python3
# made by relapse & git copilot
import sqlite3
import json
import os
import argparse
from datetime import datetime, timedelta
import csv
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from collections import defaultdict
import logging
import hashlib
import platform
import re
import sys
import time
import threading
import shutil
from typing import Optional, Iterable, Dict, Any, List

__version__ = "0.1.0"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

FILETIME_EPOCH_OFFSET = 116444736000000000
TICKS_PER_SECOND = 10_000_000

# analyzer
# weights
WEIGHTS = {
    'vt_positive': 50,
    'no_valid_signature': 15,
    'recent_replace_or_delete': 10,
    'autorun_or_scheduled': 10,
    'suspicious_location': 5,
    'no_icon_and_admin': 10
}

SUSPICIOUS_PATHS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expanduser('~'),
]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def vt_lookup(hash256: str, api_key: Optional[str] = None) -> Optional[Dict[str, Any]]:
    try:
        import requests
    except Exception:
        return None
    key = api_key or os.environ.get('VT_API_KEY')
    if not key:
        return None
    url = f'https://www.virustotal.com/api/v3/files/{hash256}'
    headers = {'x-apikey': key}
    r = requests.get(url, headers=headers, timeout=10)
    if r.status_code != 200:
        logger.debug('VirusTotal lookup failed: %s', r.status_code)
        return None
    return r.json()


def check_vt_positive(vt_report: Optional[Dict[str, Any]]) -> (bool, Optional[int]):
    if not vt_report:
        return False, None
    data = vt_report.get('data', {})
    attrs = data.get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    positives = sum(v for v in stats.values()) if stats else None
    return (positives and positives > 0), positives


def has_pe_signature(path: str) -> Optional[bool]:
    try:
        import pefile
    except Exception:
        try:
            with open(path, 'rb') as f:
                data = f.read(65536)
        except Exception:
            return None
        if b'PKCS7' in data or b'-----BEGIN CERTIFICATE-----' in data:
            return True
        return False
    try:
        pe = pefile.PE(path, fast_load=True)
        cert_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if cert_dir.Size and cert_dir.VirtualAddress:
            return True
        return False
    except Exception:
        return None


def has_requested_admin_manifest(path: str) -> Optional[bool]:
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except Exception:
        return None
    if b'<requestedExecutionLevel' in data:
        if b'requireAdministrator' in data:
            return True
        return False
    return False


def has_icon(path: str) -> Optional[bool]:
    try:
        with open(path, 'rb') as f:
            data = f.read(1_000_000)
    except Exception:
        return None
    if b'\x00\x00\x01\x00' in data or b'\x89PNG\r\n\x1a\n' in data:
        return True
    return False


def is_in_suspicious_location(path: str) -> bool:
    p = os.path.abspath(path).lower()
    for s in SUSPICIOUS_PATHS:
        if not s:
            continue
        if s.lower() in p:
            if any(x in p for x in ('\\temp', '/temp', 'appdata', 'local\\temp')):
                return True
    return False


def is_autorun_or_scheduled(path: str) -> Optional[bool]:
    if platform.system().lower() != 'windows':
        return None
    try:
        import winreg
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]
        target = os.path.abspath(path).lower()
        for hive, sub in run_keys:
            try:
                with winreg.OpenKey(hive, sub) as k:
                    for i in range(0, winreg.QueryInfoKey(k)[1]):
                        name, val, _ = winreg.EnumValue(k, i)
                        if val and target in val.lower():
                            return True
            except Exception:
                continue
        tasks_root = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'Tasks')
        if os.path.isdir(tasks_root):
            for root, _, files in os.walk(tasks_root):
                for f in files:
                    try:
                        fp = os.path.join(root, f)
                        with open(fp, 'rb') as fh:
                            content = fh.read()
                            if target.encode('utf-16le') in content or target.encode() in content:
                                return True
                    except Exception:
                        continue
        return False
    except Exception:
        return None


def recently_replaced_or_deleted(path: str, lookback_days: int = 7) -> Optional[bool]:
    if not os.path.exists(path):
        return True
    try:
        stat = os.stat(path)
        now = datetime.now()
        mtime = datetime.fromtimestamp(stat.st_mtime)
        ctime = datetime.fromtimestamp(stat.st_ctime)
        if (now - mtime).days <= lookback_days or (now - ctime).days <= lookback_days:
            return True
        return False
    except Exception:
        return None


def analyze_file(path: str, vt_api_key: Optional[str] = None) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    result['path'] = path
    result['sha256'] = sha256_file(path) if os.path.exists(path) else None
    vt_report = vt_lookup(result['sha256'], vt_api_key) if result['sha256'] else None
    vt_positive, vt_count = check_vt_positive(vt_report)
    sig = has_pe_signature(path)
    manifest_admin = has_requested_admin_manifest(path)
    icon = has_icon(path)
    autorun = is_autorun_or_scheduled(path)
    recent = recently_replaced_or_deleted(path)
    suspicious_path = is_in_suspicious_location(path)

    result['virustotal'] = {'positive': vt_positive, 'positives': vt_count, 'report': None if not vt_report else vt_report}
    result['has_signature'] = sig
    result['requested_admin'] = manifest_admin
    result['has_icon'] = icon
    result['autorun_or_scheduled'] = autorun
    result['recent_replace_or_delete'] = recent
    result['suspicious_location'] = suspicious_path

    score = 0
    if vt_positive:
        score += WEIGHTS['vt_positive']
    if sig is False:
        score += WEIGHTS['no_valid_signature']
    if recent:
        score += WEIGHTS['recent_replace_or_delete']
    if autorun:
        score += WEIGHTS['autorun_or_scheduled']
    if suspicious_path:
        score += WEIGHTS['suspicious_location']
    if (icon is False or not icon) and manifest_admin:
        score += WEIGHTS['no_icon_and_admin']

    score = min(100, max(0, int(score)))
    result['malicious_score'] = score
    if score >= 70:
        verdict = 'malicious'
    elif score >= 35:
        verdict = 'suspicious'
    else:
        verdict = 'benign'
    result['verdict'] = verdict

    return result

# end analyzer

# animation
def _is_animation_enabled() -> bool:
    if os.environ.get('ACACHE_NO_ANIMATION'):
        return False
    if not sys.stdout.isatty():
        return False
    return True

_ASCII_ACACHE = [
    "dP                ",
    "                                    88                ",
    ".d8888b. .d8888b. .d8888b. .d8888b. 88d888b. .d8888b. ",
    "88'  `88 88'  `\"\" 88'  `88 88'  `\"\" 88'  `88 88ooood8 ",
    "88.  .88 88.  ... 88.  .88 88.  ... 88    88 88.  ... ",
    "`88888P8 `88888P' `88888P8 `88888P' dP    dP `88888P' ",
    "oooooooooooooooooooooooooooooooooooooooooooooooooooooo",
    "                                                       ",
    "                                                       ",
]


def animate_acache(stop_event: threading.Event, min_duration: float = 0.5, frame_delay: float = 0.03) -> None:
    """animate ascii acache (keeps final display 3s)"""
    if not _is_animation_enabled():
        return
    start = time.time()
    max_len = max(len(l) for l in _ASCII_ACACHE)
    reveal = 0
    try:
        while True:
            if reveal < max_len:
                reveal += 1
            # draw
            out_lines = []
            for line in _ASCII_ACACHE:
                chunk = line[:reveal].ljust(len(line))
                # center
                cols = shutil.get_terminal_size((80, 20)).columns
                padding = max((cols - len(line)) // 2, 0)
                out_lines.append(' ' * padding + chunk)
            # print
            sys.stdout.write('\x1b[2J\x1b[H')
            sys.stdout.write('\n'.join(out_lines) + '\n')
            sys.stdout.flush()
            # stop condition
            if reveal >= max_len and stop_event.is_set() and (time.time() - start) >= min_duration:
                break
            time.sleep(frame_delay)
    except Exception:
        # animation must not crash the program
        pass
    finally:
        # final pause
        try:
            time.sleep(3.0)
        except Exception:
            pass
        try:
            sys.stdout.write('\x1b[2J\x1b[H')
            sys.stdout.flush()
        except Exception:
            pass


def start_animation() -> Optional[tuple]:
    if not _is_animation_enabled():
        return None
    stop_event = threading.Event()
    t = threading.Thread(target=animate_acache, args=(stop_event,), daemon=True)
    t.start()
    return stop_event, t

class ActivityCacheParser:
    """Simple parser for ActivitiesCache DB used in DFIR workflows."""
    def __init__(self, dbpath: str):
        self.dbpath = dbpath
        self.conn: Optional[sqlite3.Connection] = None
        self.cursor: Optional[sqlite3.Cursor] = None

    def connect(self) -> None:
        if not os.path.exists(self.dbpath):
            raise FileNotFoundError(f"DB file missing at {self.dbpath}")
        self.conn = sqlite3.connect(self.dbpath)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        logger.debug("Connected to DB %s", self.dbpath)

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None
            logger.debug("DB connection closed")

    @staticmethod
    def filetime_to_datetime(filetime: Optional[int]) -> Optional[datetime]:
        if filetime is None:
            return None
        try:
            unix = (int(filetime) - FILETIME_EPOCH_OFFSET) / TICKS_PER_SECOND
            return datetime.fromtimestamp(unix)
        except Exception:
            return None

    def query_activities(self, startdate: Optional[datetime] = None, enddate: Optional[datetime] = None,
                        appfilter: Optional[str] = None) -> Iterable[sqlite3.Row]:
        query = "SELECT * FROM activity"
        clauses: List[str] = []
        params: List[Any] = []
        if startdate:
            clauses.append("starttime >= ?")
            params.append(int(startdate.timestamp() * TICKS_PER_SECOND + FILETIME_EPOCH_OFFSET))
        if enddate:
            clauses.append("endtime <= ?")
            params.append(int(enddate.timestamp() * TICKS_PER_SECOND + FILETIME_EPOCH_OFFSET))
        if appfilter:
            clauses.append("appid LIKE ?")
            params.append(f"%{appfilter}%")
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        logger.debug("Executing query: %s params=%s", query, params)
        assert self.cursor is not None, "DB not connected"
        for row in self.cursor.execute(query, params):
            yield row

    def parse_json_stream(self, rows: Iterable[sqlite3.Row]) -> Iterable[Dict[str, Any]]:
        """Stream rows and yield parsed dicts to keep memory usage low."""
        for row in rows:
            rowdict: Dict[str, Any] = dict(row)
            # parse appid/payload
            appid = rowdict.get('appid')
            rowdict['appid_parsed'] = None
            if appid:
                try:
                    parsed_appid = json.loads(appid)
                    # normalize common keys from various appid payloads
                    if isinstance(parsed_appid, dict):
                        # prefer keys
                        app_name = parsed_appid.get('application') or parsed_appid.get('appName') or parsed_appid.get('displayName') or parsed_appid.get('name') or parsed_appid.get('packageFamilyName')
                        parsed_appid['__normalized_name'] = app_name
                    rowdict['appid_parsed'] = parsed_appid
                except json.JSONDecodeError:
                    rowdict['appid_parsed'] = None
            payload = rowdict.get('payload')
            rowdict['payload_parsed'] = None
            if payload:
                try:
                    rowdict['payload_parsed'] = json.loads(payload)
                except json.JSONDecodeError:
                    rowdict['payload_parsed'] = None
            # times
            if 'starttime' in rowdict:
                rowdict['starttime_readable'] = self.filetime_to_datetime(rowdict.get('starttime'))
            if 'endtime' in rowdict:
                rowdict['endtime_readable'] = self.filetime_to_datetime(rowdict.get('endtime'))
            yield rowdict

    # compatibility wrapper
    def parse_json_blobs(self, rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
        return list(self.parse_json_stream(rows))
    @staticmethod
    def export_to_csv(data: List[Dict[str, Any]], filepath: str) -> None:
        if not data:
            logger.info("No data to export")
            return
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=list(data[0].keys()))
            writer.writeheader()
            writer.writerows(data)
        logger.info("Exported to %s", filepath)

    @staticmethod
    def export_to_json(data: List[Dict[str, Any]], filepath: str) -> None:
        with open(filepath, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=4, default=str)
        logger.info("Exported to %s", filepath)

    @staticmethod
    def export_to_html(data: List[Dict[str, Any]], insights: Dict[str, Any], filepath: str, filescan_reports: Optional[List[Dict[str, Any]]] = None) -> None:
        """Write a simple interactive HTML report (uses DataTables CDN for sorting/searching/paging).
        The report includes an insights summary and a sortable table of parsed rows with expandable JSON details.
        """
        try:
            rows_html = []
            for i, entry in enumerate(data, start=1):
                app = 'unknown'
                ap = entry.get('appid_parsed')
                if isinstance(ap, dict):
                    app = ap.get('__normalized_name') or ap.get('application') or ap.get('appName') or ap.get('displayName') or ap.get('name') or ap.get('packageFamilyName') or 'unknown'
                else:
                    payload = entry.get('payload_parsed')
                    if isinstance(payload, dict):
                        app = payload.get('application') or payload.get('app') or payload.get('appName') or app
                start = entry.get('starttime_readable')
                end = entry.get('endtime_readable')
                start_s = str(start) if start else ''
                end_s = str(end) if end else ''
                duration = ''
                if start and end:
                    try:
                        duration = str((end - start).total_seconds())
                    except Exception:
                        duration = ''
                safe_json = json.dumps(entry, indent=2, default=str).replace('</', '<\/')
                rows_html.append(f"<tr><td>{i}</td><td>{app}</td><td>{start_s}</td><td>{end_s}</td><td>{duration}</td><td><button class=\"show-details\">show</button><pre class=\"hidden details\">{safe_json}</pre></td></tr>")

            filescan_section = ''
            if filescan_reports:
                filescan_section = '<h2>file scan results</h2><pre>' + json.dumps(filescan_reports, indent=2, default=str) + '</pre>'

            html = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>acache report</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
<style>
body{{font-family:Inter, Arial, Helvetica, sans-serif;background:#071428;color:#dff0ff;margin:20px}}
h1{{font-weight:700;margin-bottom:0.2em;color:#ffffff}}
.summary{{background:#0b2b4a;padding:14px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);margin-bottom:1rem;color:#dff0ff}}
.table-wrap{{background:#062238;padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);color:#dff0ff}}
table.dataTable{{background:transparent;color:#e6f6ff}}
table.dataTable thead th{{background:#0a3f6f;color:#eaf6ff}}
table.dataTable tbody tr{{border-bottom:1px solid rgba(255,255,255,0.03)}}
pre.details{{display:none;background:#021226;padding:10px;border-radius:4px;overflow:auto;max-height:240px;color:#dbeffc}}
button.show-details{{padding:6px 10px;border-radius:4px;border:1px solid rgba(255,255,255,0.06);background:#0a3f6f;color:#eaf6ff;cursor:pointer}}
a, .dataTables_wrapper .dataTables_filter input {{color:#eaf6ff}}
.dataTables_wrapper .dataTables_paginate .paginate_button{{background:transparent;color:#eaf6ff;border:1px solid rgba(255,255,255,0.03);border-radius:4px;padding:4px 8px;margin-left:4px}}
</style>
</head>
<body>
<h1>acache <small style=\"font-weight:400;color:#9ad1ff;margin-left:8px;font-size:0.6em\">made by relapse & git copilot</small></h1>
<div class="summary">
<h2>insights</h2>
<pre>{json.dumps(insights, indent=2, default=str)}</pre>
{filescan_section}
</div>
<div class="table-wrap">
<table id="acache" class="display" style="width:100%">
<thead><tr><th>#</th><th>app</th><th>start</th><th>end</th><th>duration_s</th><th>details</th></tr></thead>
<tbody>
{''.join(rows_html)}
</tbody>
</table>
</div>
<script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
<script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function(){{
  var table = $('#acache').DataTable({{pageLength: 25}});
  $('#acache').on('click','button.show-details', function(e){{
    var pre = $(this).siblings('pre.details');
    if(pre.is(':visible')){{
      pre.hide(); $(this).text('show');
    }} else {{
      pre.show(); $(this).text('hide');
    }}
  }});
}});
</script>
</body>
</html>'''
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write(html)
            logger.info('Exported HTML report to %s', filepath)
        except Exception as e:
            logger.warning('Failed to export HTML report: %s', e)

    def analyze_data(self, data: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        insights: Dict[str, Any] = {}
        appcounts: Dict[str, int] = defaultdict(int)
        timelines: List[Dict[str, Any]] = []
        total = 0
        for entry in data:
            total += 1
            app = 'unknown'
            ap = entry.get('appid_parsed')
            if isinstance(ap, dict):
                app = ap.get('__normalized_name') or ap.get('application') or ap.get('appName') or ap.get('displayName') or ap.get('name') or ap.get('packageFamilyName') or 'unknown'
            else:
                # fallback app info
                payload = entry.get('payload_parsed')
                if isinstance(payload, dict):
                    app = payload.get('application') or payload.get('app') or payload.get('appName') or app
            if not app:
                app = 'unknown'
            appcounts[app] += 1
            start = entry.get('starttime_readable')
            end = entry.get('endtime_readable')
            if start and end:
                duration = (end - start).total_seconds()
                timelines.append({'app': app, 'start': start, 'duration': duration})
        insights['app_usage_counts'] = dict(appcounts)
        insights['total_activities'] = total
        insights['timelines'] = timelines
        return insights
    @staticmethod
    def plot_timeline(insights: Dict[str, Any], savepath: Optional[str] = None) -> None:
        timelines = insights.get('timelines', [])
        if not timelines:
            logger.info("No timeline data to plot")
            return
        apps = [t['app'] for t in timelines]
        starts = [mdates.date2num(t['start']) for t in timelines]
        durations = [t['duration'] / 3600 for t in timelines]
        fig, ax = plt.subplots()
        ax.barh(apps, durations, left=starts)
        ax.xaxis_date()
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d %H:%M'))
        plt.xlabel('time')
        plt.ylabel('app')
        plt.title('activity timelines')
        fig.autofmt_xdate()
        if savepath:
            plt.savefig(savepath)
            logger.info("Plot saved to %s", savepath)
        plt.show()


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description='parse activitiescache.db for DFIR')
    ap.add_argument('dbpath', help='path to activitiescache.db')
    ap.add_argument('--startdate', help='start date filter yyyy-mm-dd')
    ap.add_argument('--enddate', help='end date filter yyyy-mm-dd')
    ap.add_argument('--appfilter', help='filter by app name')
    ap.add_argument('--exportcsv', help='export to csv file')
    ap.add_argument('--exportjson', help='export to json file')
    ap.add_argument('--plot', help='plot timeline and save to file')
    ap.add_argument('--verbose', '-v', action='store_true', help='enable verbose logging (debug)')
    ap.add_argument('--use-pandas', action='store_true', help='use pandas for exported CSVs if available')
    ap.add_argument('--version', action='version', version=__version__)
    ap.add_argument('--filescan', help='analyze files or directory for suspicious/malicious indicators')
    ap.add_argument('--filescan-recursive', action='store_true', help='recurse when filescan is a directory')
    ap.add_argument('--vt-key', help='VirusTotal API key for file scanning (optional)')
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    startdt = datetime.strptime(args.startdate, '%Y-%m-%d') if args.startdate else None
    enddt = datetime.strptime(args.enddate, '%Y-%m-%d') if args.enddate else None

    # start animation
    anim = start_animation()

    parser = ActivityCacheParser(args.dbpath)
    try:
        parser.connect()
        rows = parser.query_activities(startdt, enddt, args.appfilter)
        # materialize parsed data
        parseddata = list(parser.parse_json_stream(rows))
        insights = parser.analyze_data(parseddata)
        # stop animation
        if anim:
            stop_event, thread = anim
            stop_event.set()
            thread.join(timeout=5)
        logger.info("Insights: %s", json.dumps(insights, indent=4, default=str))
        # autosave
        try:
            db_dir = os.path.dirname(args.dbpath) or '.'
            base = os.path.splitext(os.path.basename(args.dbpath))[0]
            auto_json = os.path.join(db_dir, f"{base}.parsed.json")
            parser.export_to_json(parseddata, auto_json)
            analyzer_json = os.path.join(db_dir, f"{base}.insights.json")
            parser.export_to_json(insights, analyzer_json)
            logger.info("Auto-saved parsed data to %s and insights to %s", auto_json, analyzer_json)
        except Exception as e:
            logger.warning("Auto-save failed: %s", e)
        if args.exportcsv:
            if args.use_pandas:
                try:
                    import pandas as pd
                    df = pd.DataFrame.from_records(parseddata)
                    df.to_csv(args.exportcsv, index=False)
                    logger.info("Exported to %s using pandas", args.exportcsv)
                except Exception as e:
                    logger.warning("Pandas export failed (%s), falling back to csv module", e)
                    parser.export_to_csv(parseddata, args.exportcsv)
            else:
                parser.export_to_csv(parseddata, args.exportcsv)
        if args.exportjson:
            parser.export_to_json(parseddata, args.exportjson)
        if args.plot:
            parser.plot_timeline(insights, args.plot)

        # file scan
        if args.filescan:
            paths = []
            if os.path.isdir(args.filescan):
                if args.filescan_recursive:
                    for root, _, files in os.walk(args.filescan):
                        for f in files:
                            paths.append(os.path.join(root, f))
                else:
                    for f in os.listdir(args.filescan):
                        paths.append(os.path.join(args.filescan, f))
            else:
                paths = [args.filescan]
            reports = []
            for p in paths:
                try:
                    r = analyze_file(p, args.vt_key)
                    reports.append(r)
                    print(json.dumps(r, indent=2, default=str))
                except Exception as e:
                    logger.error("File scan failed for %s: %s", p, e)
            if args.exportjson:
                # append file_scan
                try:
                    with open(args.exportjson, 'r+', encoding='utf-8') as fh:
                        data = json.load(fh)
                        if isinstance(data, dict):
                            data.setdefault('file_scan', []).extend(reports)
                            fh.seek(0)
                            json.dump(data, fh, indent=4, default=str)
                except Exception:
                    logger.error("Failed to append file_scan to exportjson")
            if args.exportcsv:
                # filescan csv
                import csv as _csv
                csvpath = args.exportcsv
                with open(csvpath.replace('.csv', '_filescan.csv'), 'w', newline='', encoding='utf-8') as cf:
                    writer = _csv.DictWriter(cf, fieldnames=['path','sha256','malicious_score','verdict'])
                    writer.writeheader()
                    for r in reports:
                        writer.writerow({k: r.get(k) for k in ['path','sha256','malicious_score','verdict']})
    except Exception as e:
        logger.error("Error: %s", e)
        return 1
    finally:
        # autosave html
        try:
            if 'parseddata' in locals():
                db_dir = os.path.dirname(args.dbpath) or '.'
                base = os.path.splitext(os.path.basename(args.dbpath))[0]
                auto_html = os.path.join(db_dir, f"{base}.report.html")
                reports_var = locals().get('reports', None)
                try:
                    parser.export_to_html(parseddata, insights, auto_html, reports_var)
                    logger.info("Auto-saved HTML report to %s", auto_html)
                except Exception as e:
                    logger.warning("Auto HTML export failed: %s", e)
        except Exception:
            pass
        parser.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
