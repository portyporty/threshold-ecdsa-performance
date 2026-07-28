| ID | Scenario | mean (ms) | stddev (ms) | median (ms) | min (ms) | max (ms) | mean (cycles) |
|---|---|---:|---:|---:|---:|---:|---:|
| A1 | Standard ECDSA s-phase only | 0.002 | 0.000 | 0.002 | 0.002 | 0.010 | 5,459 |
| A2 | Standard ECDSA full sign | 0.980 | 0.174 | 0.905 | 0.819 | 2.428 | 2,443,741 |
| B | Bitcoin multisig 2-of-2 | 1.948 | 0.244 | 1.845 | 1.682 | 3.487 | 4,861,453 |
| C1 | Threshold ECDSA online | 0.007 | 0.003 | 0.006 | 0.006 | 0.068 | 16,212 |
| C2 | Threshold ECDSA full (presign+sign) | 0.966 | 0.150 | 0.903 | 0.824 | 1.800 | 2,410,622 |
| C3 | Threshold MPC + Paillier HE (user) | 9.607 | 0.561 | 9.519 | 8.783 | 19.706 | 23,974,063 |
