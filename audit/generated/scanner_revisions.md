# Scanner revision registry

| source SHA-256 prefix | chunks | revisions (counts) | targets | change | cross-test |
|---|---:|---|---:|---|---|
| `87f10166` | 1--7 | `ebd54ea0fbdf78287392e9be80b2578618964975` (7) | 10 | Initial campaign fingerprint; fused and mirror max-run paths already active. | Covered by the frozen pre-flight agreement suite. |
| `3598aea6` | 8--35 | `657a140a1d907a54d168c4e37b4d79c774fef539` (10), `185b8680172bb4e20be1d7765f72cda3d26cf72d` (18) | 10 | Added the point-verification mode and record reporting; the production target predicate was unchanged. | Point claims were checked by mirror, full, CPU-walk, and separate verifiers. |
| `cca301fe` | 36--78 | `062cc3cdf97ff2d158b907ed3d62c2f68884e89b` (43) | 13 | Added the three two-colour bonus targets; the already-computed r=2 max-run profile was reused. | The new bookkeeping was exercised on [1026949000,1026950000); the (3,17) path was unchanged. |
| `3b5d1049` | 79--515 | `4f9e2cf8e56c659684d2bb7269d65a89f68069b8` (1), `c3a9b9eb318f63720146c03d3032de7d5c9183e0` (274), `a93cec91826d73df4200903bda941a9c805929ff` (72), `7c1ba34b1cb09dc0bf5fd08ffc4ef2812075f066` (90) | 13 | Added aggregate congruence counters; later revisions changed the driver or theory files, not scan_gpu.cu. | Old/new TARGET and CHECKSUM outputs agreed exactly and an end-to-end test passed. |
