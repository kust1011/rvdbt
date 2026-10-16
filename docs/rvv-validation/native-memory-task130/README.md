Task130 implements exact ordinary QCG vle/vse access-site inspection and ordered
load-chunk publication. It does not implement native SIMD fault recovery.

See [the full contract/result](https://github.com/kust1011/rvdbt/blob/9dfc020b2aa7e98d068d954555b5902082538702/SESSION0_RESULT_130.md). The receipt
archive contains first/final build/check streams, actual compiler flags/cache,
source/dependency equality, emitted binary/site/disassembly files, 16 one-time
fault captures and three unchanged original ACT normal-call receipts.

Local original raw is `/home/user/research/materials/task130-native-memory-raw-20261013`;
remote source/build/raw is `xbd:/home/vick/rvdbt-native-memory-task130`.
Inspect the manifest and LOCAL_RAW_AUDIT.json before making derived outputs.
Run `scripts/audit_native_memory_task130.py` on a separate extracted copy: it
executes objdump, writes derived disassembly/JSON, and executes no guests.
The replay script runs only its three explicit original normal calls; it needs
the retained original xbd adapter/inputs. No full corpus replay is included.
