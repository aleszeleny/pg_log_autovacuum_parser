#!/usr/bin/env python3
# coding: utf-8

import sys
import os
import re
#import regex

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
                \s+(?P<log_type>[A-Z]+)
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
autovacuum_data_pattern = r'''
    automatic\svacuum\sof\stable\s+
    \"(?P<dbname>\w+)\.(?P<schemaname>\w+)\.(?P<tablename>\w+)\":\s+
    (?P<vacuum_data>
        (?P<vacuum_index_scans>index\sscans:\s+
            (?P<index_scans>\d+)
        )
        (?:
            \n\s+
            (?P<vacuum_pages>
                pages:\s+(?:(?P<vacuum_pages_removed>\d+)\s+removed).*
            )
            |(?:\n\s+(?P<vacuum_tuples>tuples:\s+(?:(?P<vacuum_tuples_removed>\d+)\s+removed).*))
            |(?:\n\s+(?P<vacuum_idx_scan_not_needed>index\sscan\snot\sneeded:\s+.*))
            |(?:\n\s+(?P<vacuum_idx_scan_bypassed>index\sscan\sbypassed:\s+.*))
            |(?:\n\s+(?P<vacuum_idx_scan_needed>index\sscan\sneeded:\s+.*))
            |(?:\n\s+(?P<vacuum_idx>index\s"(?P<vacuum_idx_name>\w+)":\s+.*))
            |(?:\n\s+(?P<vacuum_io_timings>I/O\s+timings:\s+.*))
            |(?:\n\s+(?P<vacuum_avg_read_rate>avg\s+read\s+rate:\s+.*))
            |(?:\n\s+(?P<vacuum_buffer_usage>buffer\s+usage:\s+.*))
            |(?:\n\s+(?P<vacuum_wal_usage>WAL\susage:\s+.*))
            |(?:\n\s+(?P<vacuum_system_usage>system\s+usage:\s+.*))
            |(?:\n\s+(?P<unknown>[^:]+:\s+.*))
        )*
    )
'''

def parse_autovacuum(log_timestamp, vacuum_data):
    autovacuum_data = re_autovacuum_data.search(vacuum_data)
    if autovacuum_data:
        print(
                '%s\t%s.%s.%s: removed: %s pages, %s tuples, unknown entries: %s' % (
                      log_timestamp
                    , autovacuum_data.group('dbname')
                    , autovacuum_data.group('schemaname')
                    , autovacuum_data.group('tablename')
                    , autovacuum_data.group('vacuum_pages_removed')
                    , autovacuum_data.group('vacuum_tuples_removed')
                    , autovacuum_data.group('unknown')
                )
        )

def main():
    # https://docs.python.org/3/library/signal.html#note-on-sigpipe
    # https://stackoverflow.com/questions/14207708/ioerror-errno-32-broken-pipe-when-piping-prog-py-othercmd
    try:
        with open(sys.argv[1], 'r') if (len(sys.argv) > 1 and sys.argv[1] != "-") else sys.stdin as logfile:
            pg_log_file = logfile.read()

            for m in re_log_entry.finditer(pg_log_file):
                log_msg = m.group('log_msg')
                # print(log_msg)

                if ( log_msg and re_log_autovacuum.match(log_msg) ):
                    parse_autovacuum(m.group('log_entry_timestamp'), log_msg)
        sys.stdout.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)  # Python exits with error code 1 on EPIPE

re_log_entry = re.compile(log_entry_pattern, re.MULTILINE | re.VERBOSE)
re_log_autovacuum = re.compile(log_autovacuum_pattern)
#re_autovacuum_data = regex.compile(autovacuum_data_pattern, re.MULTILINE)
re_autovacuum_data = re.compile(autovacuum_data_pattern, re.MULTILINE | re.VERBOSE)

if __name__ == '__main__':
    main()