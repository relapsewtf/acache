#!/usr/bin/env python3
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
from typing import Optional, Iterable, Dict, Any, List

__version__ = "0.1.0"

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

FILETIME_EPOCH_OFFSET = 116444736000000000
TICKS_PER_SECOND = 10_000_000


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

    def parse_json_blobs(self, rows: Iterable[sqlite3.Row]) -> List[Dict[str, Any]]:
        parsed: List[Dict[str, Any]] = []
        for row in rows:
            rowdict: Dict[str, Any] = dict(row)
            # parse appid/payload
            appid = rowdict.get('appid')
            if appid:
                try:
                    rowdict['appid_parsed'] = json.loads(appid)
                except json.JSONDecodeError:
                    rowdict['appid_parsed'] = None
            payload = rowdict.get('payload')
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
            parsed.append(rowdict)
        return parsed

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

    def analyze_data(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        insights: Dict[str, Any] = {}
        appcounts: Dict[str, int] = defaultdict(int)
        timelines: List[Dict[str, Any]] = []
        for entry in data:
            app = (entry.get('appid_parsed') or {}).get('application') if entry.get('appid_parsed') else 'unknown'
            if not app:
                app = 'unknown'
            appcounts[app] += 1
            start = entry.get('starttime_readable')
            end = entry.get('endtime_readable')
            if start and end:
                duration = (end - start).total_seconds()
                timelines.append({'app': app, 'start': start, 'duration': duration})
        insights['app_usage_counts'] = dict(appcounts)
        insights['total_activities'] = len(data)
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
        durations = [t['duration'] / 3600 for t in timelines]  # hours
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
    ap.add_argument('--version', action='version', version=__version__)
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    startdt = datetime.strptime(args.startdate, '%Y-%m-%d') if args.startdate else None
    enddt = datetime.strptime(args.enddate, '%Y-%m-%d') if args.enddate else None

    parser = ActivityCacheParser(args.dbpath)
    try:
        parser.connect()
        rows = parser.query_activities(startdt, enddt, args.appfilter)
        parseddata = parser.parse_json_blobs(rows)
        insights = parser.analyze_data(parseddata)
        logger.info("Insights: %s", json.dumps(insights, indent=4, default=str))
        if args.exportcsv:
            parser.export_to_csv(parseddata, args.exportcsv)
        if args.exportjson:
            parser.export_to_json(parseddata, args.exportjson)
        if args.plot:
            parser.plot_timeline(insights, args.plot)
    except Exception as e:
        logger.error("Error: %s", e)
        return 1
    finally:
        parser.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
