# Performance Benchmark Report: 

Generated on: 2025-07-05 16:48:51

## Results Summary

| Test | Duration (s) | Peak Memory (MB) | Throughput (files/s) | Notes |
|------|--------------|------------------|----------------------|-------|
| _sequential | 2.13 | 176.6 | 55.9 |  |
| _parallel_2p | 0.77 | 289.9 | 154.1 |  |
| _cached | 0.00 | 323.0 | 43781.9 | Speedup: 399.44x, Hit rate: 100.00% |

## Performance Analysis

**Fastest configuration**: _cached (0.00s)

**Average peak memory usage**: 263.2 MB

## Recommendations

- **Parallel processing**: Use 2 processes for 2.75x speedup
- **Caching**: Highly effective with 100.00% hit rate
