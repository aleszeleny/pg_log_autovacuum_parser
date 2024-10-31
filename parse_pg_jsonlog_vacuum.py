#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import re
import json
from datetime import datetime

log_entry_pattern = r'''
    (?P<log_entry>^
        (?P<log_header>
            (?P<log_entry_timestamp>
                \d{4}(?:-\d{2}){2}\s(?:\d{2}:?){3}\s[A-Z]+
            )
            \s
            \[(?P<pid>\d+)\]
        )
        :\s+
        (?P<log_data>
            (?P<log_metadata>
                \[(?P<pid_lineno>\d+)-\d+\]
                \s+user=(?P<dbuser>[^,\s]*)\s*
                ,\s*db=(?P<dbname>[^,\s]*)\s*
                ,\s*host=(?P<client_host>[^,\s]*)\s*
                ,\s*app=(?P<application_name>.*)
                \s+(?P<log_type>[A-Z]+)e`
            )
            :\s+
            (?P<log_msg>
                .*
                (?:
                    \n
                    (?!\d{4}(?:-\d{2}){2}\s(\d{2}:?){3}\s[A-Z]+\s\[\d+\]:)
                    .*
                )*
            )
        )

    )
'''

log_autovacuum_pattern = r'automatic vacuum of table'
autovacuum_data_pattern = r'''automatic\svacuum\sof\stable\s+
    \"(?P<dbname>\w+)\.(?P<schemaname>\w+)\.(?P<tablename>\w+)\":\s+
    (?P<vacuum_data>
        (?P<vacuum_index_scans>index\sscans:\s+
            (?P<index_scans>\d+).*
        )
        (?:
            \n\s*
                (?P<vacuum_pages>
                    pages:\s+(?:(?P<vacuum_pages_removed>\d+)\s+removed)
                    (,\s+(?P<vacuum_pages_remain>\d+)\s+remain)?
                    (,\s+(?P<vacuum_pages_scanned>\d+)\s+scanned)?
                    (\s+\((?P<vacuum_pages_scanned_pct>\d[^%]*)%\s+of\s+total\))*
                    .*
                )
            |
                (?:\n\s*
                    (?P<vacuum_tuples>
                        tuples:\s+(?:(?P<vacuum_tuples_removed>\d+)\s+removed)
                        (,\s+(?P<vacuum_tuples_remain>\d+)\s+remain)?
                        (,\s+(?P<vacuum_tuples_dead_nr>\d[^%]*)\s+are\s+dead\s+but\s+not\s+yet\s+removable)?
                        .*
                    )
                )
            |
                (?:\n\s*
                    (?P<removable_cutoff>
                        removable\s+cutoff:\s+(?:(?P<removable_cutoff_txid>\d+))
                        (,\s+which\s+was\s+(?P<removable_cutoff_xids_age>\d+)\s+XIDs\s+old\s+when\s+operation\s+ended)?
                        .*
                    )
                )
        )*
    )
'''

            # |(?:\n\s*(?P<vacuum_tuples>tuples:\s+(?:(?P<vacuum_tuples_removed>\d+)\s+removed).*))
            # |(?:\n\s*(?P<vacuum_idx_scan_bypassed>index\sscan\sbypassed:\s+.*))
            # |(?:\n\s*(?P<vacuum_idx_scan_needed>index\sscan\sneeded:\s+.*))
            # |(?:\n\s*(?P<vacuum_idx>index\s\"(?P<vacuum_idx_name>\w+)\":\s+.*))
            # |(?:\n\s*(?P<vacuum_idx_scan_not_needed>index\sscan\snot\sneeded:\s+.*))
            # |(?:\n\s*(?P<vacuum_io_timings>I/O\s+timings:\s+.*))
            # |(?:\n\s*(?P<vacuum_avg_read_rate>avg\s+read\s+rate:\s+.*))
            # |(?:\n\s*(?P<vacuum_buffer_usage>buffer\s+usage:\s+.*))
            # |(?:\n\s*(?P<vacuum_wal_usage>WAL\susage:\s+.*))
            # |(?:\n\s*(?P<vacuum_system_usage>system\s+usage:\s+.*))
            # |(?:\n\s*(?P<unknown>[^:]+:\s+.*))



def parse_autovacuum(autovacuum_log):
    log_ts = datetime.strptime(autovacuum_log["timestamp"], log_ts_format)
    log_timestamp = log_ts.strftime('%Y-%m-%d, %H, %M')
    # log_timestamp = log_ts.strftime('%Y-%m-%d %H:%M:%S.%f %Z')
    autovacuum_data = re_autovacuum_data.search(autovacuum_log["message"])
    # print(type(autovacuum_log["message"]))
    # print(autovacuum_log["message"])
    # print()
    if autovacuum_data:
        print(
                (
                    "%s, %s.%s.%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s"
                    # "%s\t%s.%s.%s: index scans: %s, "
                    # "pages: ( %s removed, %s remain, %s scanned - %s %% of total), "
                    # "tuples: ( %s removed, %s remain, %s dead not removable ), "
                    # "removable cutoff: %s, which was %s XIDs old when operation ended"
                ) % (
                # '%s\t%s.%s.%s: index scans: %s, removed: %s pages, remain: %s pages, scanned: %s pages, removed %s tuples, unknown entries: %s' % (
                      log_timestamp
                    , autovacuum_data.group('dbname')
                    , autovacuum_data.group('schemaname')
                    , autovacuum_data.group('tablename')
                    , autovacuum_data.group('index_scans')
                    , autovacuum_data.group('vacuum_pages_removed')
                    , autovacuum_data.group('vacuum_pages_remain')
                    , autovacuum_data.group('vacuum_pages_scanned')
                    , autovacuum_data.group('vacuum_pages_scanned_pct')
                    , autovacuum_data.group('vacuum_tuples_removed')
                    , autovacuum_data.group('vacuum_tuples_remain')
                    , autovacuum_data.group('vacuum_tuples_dead_nr')
                    , autovacuum_data.group('removable_cutoff_txid')
                    , autovacuum_data.group('removable_cutoff_xids_age')
                    # , autovacuum_data.group('unknown')
                )
        )

def main():
    # https://docs.python.org/3/library/signal.html#note-on-sigpipe
    # https://stackoverflow.com/questions/14207708/ioerror-errno-32-broken-pipe-when-piping-prog-py-othercmd
    try:
        with open(sys.argv[1], 'r') if (len(sys.argv) > 1 and sys.argv[1] != "-") else sys.stdin as logfile:

            for log_entry in logfile:
                log_data = json.loads(log_entry)
                # print(json.dumps(log_data, indent=2))

                if ( log_data["backend_type"] == "autovacuum worker" ) and ( re_log_autovacuum.match(log_data["message"]) ):
                    # print(json.dumps(log_data, indent=2))
                    parse_autovacuum(log_data)
        sys.stdout.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)  # Python exits with error code 1 on EPIPE

log_ts_format = "%Y-%m-%d %H:%M:%S.%f %Z"
re_log_entry = re.compile(log_entry_pattern, re.MULTILINE | re.VERBOSE)
re_log_autovacuum = re.compile(log_autovacuum_pattern)
#re_autovacuum_data = regex.compile(autovacuum_data_pattern, re.MULTILINE)
re_autovacuum_data = re.compile(autovacuum_data_pattern, re.VERBOSE | re.MULTILINE)
vacuum_data = []

if __name__ == '__main__':
    main()

# # Vacuum log entries (pg16) examples:
# automatic vacuum of table "xxx.yyy.zzz": index scans: 0
# pages: 0 removed, 8566 remain, 589 scanned (6.88% of total)
# tuples: 8 removed, 8871 remain, 524 are dead but not yet removable
# removable cutoff: 289809785, which was 1298 XIDs old when operation ended
# frozen: 5 pages from table (0.06% of total) had 14 tuples frozen
# index scan bypassed: 11 pages from table (0.13% of total) have 11 dead item identifiers
# I/O timings: read: 0.000 ms, write: 0.000 ms
# avg read rate: 0.000 MB/s, avg write rate: 0.000 MB/s
# buffer usage: 1223 hits, 0 misses, 0 dirtied
# WAL usage: 13 records, 0 full page images, 1181 bytes
# system usage: CPU: user: 0.00 s, system: 0.00 s, elapsed: 0.00 s

# automatic vacuum of table "xxx.yyy.zzz": index scans: 1
# pages: 0 removed, 590 remain, 115 scanned (19.49% of total)
# tuples: 129 removed, 18502 remain, 92 are dead but not yet removable
# removable cutoff: 289809785, which was 1327 XIDs old when operation ended
# frozen: 1 pages from table (0.17% of total) had 34 tuples frozen
# index scan needed: 40 pages from table (6.78% of total) had 428 dead item identifiers removed
# index "pk_xxx": pages: 94 in total, 0 newly deleted, 0 currently deleted, 0 reusable
# index "ux_xxx": pages: 2 in total, 0 newly deleted, 0 currently deleted, 0 reusable
# index "ux_zzz": pages: 2 in total, 0 newly deleted, 0 currently deleted, 0 reusable
# I/O timings: read: 0.000 ms, write: 0.000 ms
# avg read rate: 0.000 MB/s, avg write rate: 4.469 MB/s
# buffer usage: 425 hits, 0 misses, 1 dirtied
# WAL usage: 149 records, 0 full page images, 10712 bytes
# system usage: CPU: user: 0.00 s, system: 0.00 s, elapsed: 0.00 s

# automatic vacuum of table "xxx.yyy.zzz": index scans: 0
# pages: 0 removed, 268873 remain, 7845 scanned (2.92% of total)
# tuples: 0 removed, 3589280 remain, 0 are dead but not yet removable
# removable cutoff: 289809785, which was 1335 XIDs old when operation ended
# frozen: 757 pages from table (0.28% of total) had 10390 tuples frozen
# index scan not needed: 0 pages from table (0.00% of total) had 0 dead item identifiers removed
# I/O timings: read: 18.272 ms, write: 0.000 ms
# avg read rate: 48.657 MB/s, avg write rate: 242.241 MB/s
# buffer usage: 15355 hits, 465 misses, 2315 dirtied
# WAL usage: 3825 records, 2316 full page images, 18627556 bytes
# system usage: CPU: user: 0.03 s, system: 0.00 s, elapsed: 0.07 s

# automatic vacuum of table "xxx.yyy.zzz": index scans: 1
# pages: 0 removed, 120 remain, 120 scanned (100.00% of total)
# tuples: 145 removed, 649 remain, 0 are dead but not yet removable
# removable cutoff: 289811113, which was 531 XIDs old when operation ended
# new relfrozenxid: 286371019, which is 7110685 XIDs ahead of previous value
# new relminmxid: 68673587, which is 7106 MXIDs ahead of previous value
# frozen: 0 pages from table (0.00% of total) had 0 tuples frozen
# index scan needed: 63 pages from table (52.50% of total) had 160 dead item identifiers removed
# index "ix_xx1": pages: 11 in total, 0 newly deleted, 3 currently deleted, 3 reusable
# index "ix_xx2": pages: 41 in total, 1 newly deleted, 28 currently deleted, 27 reusable
# index "ix_xx3": pages: 5 in total, 0 newly deleted, 0 currently deleted, 0 reusable
# index "pk_xxx": pages: 41 in total, 1 newly deleted, 28 currently deleted, 27 reusable
# I/O timings: read: 0.000 ms, write: 0.000 ms
# avg read rate: 0.000 MB/s, avg write rate: 174.164 MB/s
# buffer usage: 562 hits, 0 misses, 21 dirtied
# WAL usage: 219 records, 6 full page images, 15754 bytes
# system usage: CPU: user: 0.00 s, system: 0.00 s, elapsed: 0.00 s