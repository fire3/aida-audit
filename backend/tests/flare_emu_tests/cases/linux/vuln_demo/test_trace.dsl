option trace = true
option trace_mem = true
call path_coverage(5, 11)
report "trace_report.json" include_trace=true
