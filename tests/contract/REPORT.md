# NHDD 修复管线契约报告 (contract report)

基线口径: Go dev 版 bad/ 隔离。v9 为原语级 harness,不做隔离判定。

- go: ok (17 fixtures)
- python: ok (17 fixtures)
- **v9: SKIPPED** — build failed: In file included from D:\project\NHDD\NHDD-cpp-modular\src/so_dumper.hpp:10,
                 from D:\project\NHDD\tests\contract\v9_harness.cpp:20:
D:\project\NHDD\NHDD-cpp-modular\src/process_memory.hpp:10:10: fatal error: sys/uio.h: No such file or directory
   10 | #include <sys/uio.h>
      |          ^~~~~~~~~~~
compilation terminated.

| fixture | go | python | v9 | go==py bytes |
|---|---|---|---|---|
| dex_valid.dex | OK | OK | SKIP | yes |
| dex_bad_adler32.dex | FIXED | FIXED | SKIP | yes |
| dex_bad_sha1.dex | FIXED | FIXED | SKIP | yes |
| dex_filesize_low.dex | FIXED | FIXED | SKIP | yes |
| dex_header_size_bad.dex | FIXED | FIXED | SKIP | yes |
| dex_endian_bad.dex | FIXED | FIXED | SKIP | yes |
| dex_maplist_off_bad.dex | FIXED | FIXED | SKIP | yes |
| dex_maplist_count_huge.dex | FIXED | FIXED | SKIP | yes |
| dex_too_small.dex | BAD | BAD | SKIP | yes |
| dex_magic_erased.dex | BAD | BAD | SKIP | yes |
| so_valid.so | OK | OK | SKIP | yes |
| so_magic_erased.so | FIXED | FIXED | SKIP | yes |
| so_offset_skew.so | FIXED | FIXED | SKIP | yes |
| so_et_exec.so | BAD | BAD | SKIP | yes |
| so_tiny.so | BAD | BAD | SKIP | yes |
| so_not_elf.so | BAD | BAD | SKIP | yes |
| so_phnum_bogus.so | BAD | BAD | SKIP | yes |

## 差异

- 无 (python 与 go 基线完全一致)
