# Audit of the aggregate re-scan of chunks 1--17

Status: **PASS_AGGREGATE_COUNTS**.

| modulus `r` | re-scan `sum(HISTO[r])` | preregistered separate-source count |
|---:|---:|---:|
| 2 | 1,641,614 | 1,641,614 |
| 3 | 821,005 | 821,005 |
| 4 | 820,559 | 820,559 |
| 5 | 410,333 | 410,333 |
| 6 | 821,005 | 821,005 |
| 7 | 273,695 | 273,695 |
| 8 | 410,485 | 410,485 |
| 9 | 273,955 | 273,955 |

The comparison is aggregate over one 34,000,000-wide invocation. It does not
supply 17 per-chunk histograms and does not prove identity of ordered prime lists.
