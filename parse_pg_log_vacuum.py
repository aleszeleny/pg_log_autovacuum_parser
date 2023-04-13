#!/usr/bin/env python3
# coding: utf-8

# In[162]:


import sys
import re
#import regex

pg_log_file_name = str(sys.argv[1])
# pg_log_file_name = 'test.log'

log_entry_pattern = r'(?P<log_entry>^(?P<log_header>(?P<log_entry_timestamp>\d{4}(?:-\d{2}){2}\s(?:\d{2}:?){3}\s[A-Z]+)\s\[(?P<pid>\d+)\]):\s+(?P<log_data>(?P<log_metadata>\[(?P<pid_lineno>\d+)-\d+\]\s+user=(?P<dbuser>[^,\s]*)\s*,\s*db=(?P<dbname>[^,\s]*)\s*,\s*host=(?P<client_host>[^,\s]*)\s*,\s*app=(?P<application_name>.*)\s+(?P<log_type>[A-Z]+)):\s+(?P<log_msg>.*(?:\n(?!\d{4}(?:-\d{2}){2}\s(\d{2}:?){3}\s[A-Z]+\s\[\d+\]:).*)*)))'
log_autovacuum_pattern = r'automatic vacuum of table'
autovacuum_data_pattern = r'automatic vacuum of table\s\"(?P<dbname>\w+)\.(?P<schemaname>\w+)\.(?P<tablename>\w+)\":\s+(?P<vacuum_data>(?P<vacuum_index_scans>index scans:\s+(?P<index_scans>\d+))(?:\n\s+(?P<vacuum_pages>pages:\s+(?:(?P<vacuum_pages_removed>\d+)\s+removed).*)|(?:\n\s+(?P<vacuum_tuples>tuples:\s+(?:(?P<vacuum_tuples_removed>\d+)\s+removed).*))|(?:\n\s+(?P<vacuum_idx_scan_not_needed>index scan not needed:\s+.*))|(?:\n\s+(?P<vacuum_io_timings>I/O\s+timings:\s+.*))|(?:\n\s+(?P<vacuum_avg_read_rate>avg\s+read\s+rate:\s+.*))|(?:\n\s+(?P<vacuum_buffer_usage>buffer\s+usage:\s+.*))|(?:\n\s+(?P<vacuum_wal_usage>WAL\susage:\s+.*))|(?:\n\s+(?P<vacuum_system_usage>system\s+usage:\s+.*))|(?:\n\s+(?P<unknown>[^:]+:\s+.*)))*)'

re_log_entry = re.compile(log_entry_pattern, re.MULTILINE)
re_log_autovacuum = re.compile(log_autovacuum_pattern)
#re_autovacuum_data = regex.compile(autovacuum_data_pattern, re.MULTILINE)
re_autovacuum_data = re.compile(autovacuum_data_pattern, re.MULTILINE)


# In[163]:


with open(pg_log_file_name, 'r') as logfile:
    pg_log_file = logfile.read()


# In[164]:


# for m in re.finditer(log_entry_pattern, pg_log_file, re.MULTILINE):
#     print('\n%02d-%02d: %s' % (m.start(), m.end(), m.group('log_entry')))


# In[165]:


# for m in re_log_entry.finditer(pg_log_file):
#     print('\n%02d-%02d: %s' % (m.start(), m.end(), m.group('log_entry')))


# In[166]:


def parse_autovacuum(log_timestamp, vacuum_data):
    autovacuum_data = re_autovacuum_data.search(vacuum_data)
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


# In[167]:


for m in re_log_entry.finditer(pg_log_file):
    log_msg = m.group('log_msg')
            
    if re_log_autovacuum.match(log_msg):
        parse_autovacuum(m.group('log_entry_timestamp'), log_msg)

