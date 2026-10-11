# Current compact RVV scope

Generated saved index: **627 forms / 595 applicable / 32 excluded; checked union 595**.

Task90 reviewed Ara89 overlay on immutable Task87 / recorded October 7 routes; static implementation classes copied from the recorded October 7 route matrix.
This compact index is not raw evidence, a new execution, or a measurement of semantic depth.
Suite/stage sets overlap. A dash means no established membership in that saved set;
it does not mean an instruction is unsupported. Candidate/configuration/checker/raw details
remain in separately retained bindings. Runtime route and depth are not inferred.

See [inputs, reproduction and retrieval limits](rvv-validation/current-scope/README.md)
and the separate [Task80 real smoke](rvv-validation/smoke-task80/README.md).

| Suite | Target/result checked | Coupled endpoint |
|---|---:|---:|
| ACT | 590 | 0 |
| Ara | 422 | 0 |
| CHIPS | 595 | 0 |
| CTK | 0 | 0 |
| FORCE-RISCV | 0 | 0 |
| QEMU | 0 | 0 |
| RVISmith | 0 | 43 |
| RVV-ATG | 434 | 0 |
| RVVTS | 0 | 58 |
| RiESCUE | 0 | 0 |
| SiFive RIF | 200 | 125 |
| Tenstorrent | 0 | 0 |
| libriscv | 0 | 198 |
| rv32emu | 0 | 0 |

## Exact form membership

Recorded route IDs refer to the static implementation-class legend below.

| Form | Profile | Family | Checked suites | Endpoint suites | Recorded routes |
|---|---|---|---|---|---|
| vaadd.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vavg/1 |
| vaadd.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vavg/1 |
| vaaddu.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vavg/1 |
| vaaddu.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vavg/1 |
| vadc.vim | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vadc/1 |
| vadc.vvm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vadc/1 |
| vadc.vxm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vadd.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vadd_vi/1;vialu/1 |
| vadd.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;RVVTS;SiFive RIF;libriscv | vadd_vv/1;vialu/1 |
| vadd.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vadd_vx/1;vialu/1 |
| vand.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | libriscv | vialu/1 |
| vand.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vand_vv/1;vialu/1 |
| vand.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vialu/1 |
| vasub.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vavg/1 |
| vasub.vx | REQUIRED | fixed_point | ACT;CHIPS;RVV-ATG;SiFive RIF | RVISmith | vavg/1 |
| vasubu.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vavg/1 |
| vasubu.vx | REQUIRED | fixed_point | ACT;CHIPS;RVV-ATG;SiFive RIF | — | vavg/1 |
| vcompress.vm | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vcompress/1 |
| vcpop.m | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmaskpop/1 |
| vdiv.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vimul/1 |
| vdiv.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | — | vimul/1 |
| vdivu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vimul/1 |
| vdivu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | — | vimul/1 |
| vfadd.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vfalu/1 |
| vfadd.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vfalu/1 |
| vfclass.v | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfunary1/1 |
| vfcvt.f.x.v | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfcvt/1 |
| vfcvt.f.xu.v | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfcvt/1 |
| vfcvt.rtz.x.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | libriscv | vfcvt/1 |
| vfcvt.rtz.xu.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | libriscv | vfcvt/1 |
| vfcvt.x.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfcvt.xu.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfdiv.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfdiv.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vfalu/1 |
| vfirst.m | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmaskpop/1 |
| vfmacc.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfmacc.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vfma/1 |
| vfmadd.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfmadd.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfmax.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfmax.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfmerge.vfm | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfmerge/1 |
| vfmin.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfmin.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfmsac.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfma/1 |
| vfmsac.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfmsub.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfma/1 |
| vfmsub.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfmul.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfmul.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVISmith;RVVTS;libriscv | vfalu/1 |
| vfmv.f.s | REQUIRED | floating_point | Ara;CHIPS | libriscv | vfmvfs/1 |
| vfmv.s.f | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfmvsf/1 |
| vfmv.v.f | REQUIRED | floating_point | ACT;Ara;CHIPS | — | vfmerge/1 |
| vfncvt.f.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfcvt/1 |
| vfncvt.f.x.w | REQUIRED | floating_point | ACT;Ara;CHIPS | — | vfcvt/1 |
| vfncvt.f.xu.w | REQUIRED | floating_point | ACT;Ara;CHIPS | — | vfcvt/1 |
| vfncvt.rod.f.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS | — | vfcvt/1 |
| vfncvt.rtz.x.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | libriscv | vfcvt/1 |
| vfncvt.rtz.xu.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfncvt.x.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfncvt.xu.f.w | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfnmacc.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfma/1 |
| vfnmacc.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfnmadd.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfma/1 |
| vfnmadd.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfnmsac.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfnmsac.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfnmsub.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfma/1 |
| vfnmsub.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfma/1 |
| vfrdiv.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfrec7.v | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfunary1/2 |
| vfredmax.vs | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfred/1 |
| vfredmin.vs | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfred/1 |
| vfredosum.vs | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfred/1 |
| vfredusum.vs | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfred/1 |
| vfrsqrt7.v | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfunary1/2 |
| vfrsub.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfsgnj.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfsgnj.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfsgnjn.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfsgnjn.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfsgnjx.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfalu/1 |
| vfsgnjx.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfalu/1 |
| vfslide1down.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vfslide1up.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vfsqrt.v | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfunary1/3 |
| vfsub.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVISmith | vfalu/1 |
| vfsub.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | RVISmith;RVVTS;libriscv | vfalu/1 |
| vfwadd.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwadd.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwadd.wf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwadd.wv | REQUIRED | floating_point | ACT;CHIPS;RVV-ATG | libriscv | vfwarith/1 |
| vfwcvt.f.f.v | REQUIRED | floating_point | Ara;CHIPS | libriscv | vfcvt/1 |
| vfwcvt.f.x.v | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfcvt/1 |
| vfwcvt.f.xu.v | REQUIRED | floating_point | ACT;Ara;CHIPS | libriscv | vfcvt/1 |
| vfwcvt.rtz.x.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfwcvt.rtz.xu.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfwcvt.x.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfwcvt.xu.f.v | REQUIRED | floating_point | ACT;Ara;CHIPS;SiFive RIF | — | vfcvt/1 |
| vfwmacc.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwmacc.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwmsac.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwmsac.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfwarith/1 |
| vfwmul.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwmul.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfwarith/1 |
| vfwnmacc.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwnmacc.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfwarith/1 |
| vfwnmsac.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwnmsac.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwredosum.vs | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | libriscv | vfwred/1 |
| vfwredusum.vs | REQUIRED | floating_point | ACT;Ara;CHIPS | — | vfwred/1 |
| vfwsub.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwsub.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwsub.wf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vfwsub.wv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG | — | vfwarith/1 |
| vid.v | REQUIRED | mask_to_integer | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vid/1 |
| viota.m | REQUIRED | mask_to_integer | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmunary/1 |
| vl1re16.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vlNre/1 |
| vl1re32.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vlNre/1 |
| vl1re64.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS | SiFive RIF | vlNre/1 |
| vl1re8.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | RVISmith;SiFive RIF;libriscv | vlNre/1 |
| vl2re16.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vlNre/1 |
| vl2re32.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vlNre/1 |
| vl2re64.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS | SiFive RIF;libriscv | vlNre/1 |
| vl2re8.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlNre/1 |
| vl4re16.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlNre/1 |
| vl4re32.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vlNre/1 |
| vl4re64.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS | — | vlNre/1 |
| vl4re8.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlNre/1 |
| vl8re16.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlNre/1 |
| vl8re32.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlNre/1 |
| vl8re64.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS | — | vlNre/1 |
| vl8re8.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlNre/1 |
| vle16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vle/1 |
| vle16ff.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vleff/1 |
| vle32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vle/1 |
| vle32ff.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vleff/1 |
| vle64.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vle/1 |
| vle64ff.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vleff/1 |
| vle8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vle/1 |
| vle8ff.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vleff/1 |
| vlm.v | REQUIRED | mask_memory | ACT;Ara;CHIPS | RVISmith;SiFive RIF;libriscv | vlm/1 |
| vloxei16.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | RVISmith;libriscv | vlxei/1 |
| vloxei32.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | — | vlxei/1 |
| vloxei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlxei/1 |
| vloxei8.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | RVISmith | vlxei/1 |
| vloxseg2ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg2ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg2ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg2ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg3ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg3ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg3ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg3ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg4ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg4ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg4ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg4ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg5ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg5ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg5ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg5ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg6ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg6ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg6ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg6ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg7ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg7ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg7ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg7ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg8ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg8ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vloxseg8ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vloxseg8ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vlseg/1 |
| vlse16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vlse/1 |
| vlse32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vlse/1 |
| vlse64.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vlse/1 |
| vlse8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vlse/1 |
| vlseg2e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg2e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg2e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlseg2e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg2e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlseg2e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg2e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg2e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg3e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg3e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg3e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg3e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg3e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlseg3e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg3e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlseg3e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg4e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlseg4e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg4e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg4e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg4e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlseg4e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg4e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlseg4e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg5e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg5e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg5e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg5e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg5e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlseg5e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg5e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg5e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg6e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg6e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg6e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg6e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg6e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlseg6e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg6e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg6e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg7e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg7e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg7e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg7e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg7e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlseg7e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg7e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg7e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg8e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg8e16ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg8e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlseg8e32ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg8e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlseg8e64ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlseg8e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlseg8e8ff.v | REQUIRED | data_memory | ACT;CHIPS | — | vleff/1 |
| vlsseg2e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg2e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vlseg/1 |
| vlsseg2e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlsseg2e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg3e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg3e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg3e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlsseg3e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg4e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg4e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg4e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlsseg4e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg5e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg5e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg5e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlsseg5e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg6e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg6e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg6e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlsseg6e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg7e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg7e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg7e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vlseg/1 |
| vlsseg7e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg8e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg8e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vlsseg8e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vlseg/1 |
| vlsseg8e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxei16.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vlxei/1 |
| vluxei32.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vlxei/1 |
| vluxei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlxei/1 |
| vluxei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vlxei/1 |
| vluxseg2ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg2ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg2ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg2ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg3ei16.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg3ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg3ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg3ei8.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg4ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg4ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg4ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg4ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg5ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg5ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg5ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg5ei8.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg6ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg6ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg6ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg6ei8.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg7ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg7ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg7ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg7ei8.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg8ei16.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg8ei32.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vluxseg8ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vlseg/1 |
| vluxseg8ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vlseg/1 |
| vmacc.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/2 |
| vmacc.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vimul/2 |
| vmadc.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vadc/1 |
| vmadc.vim | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vadc/1 |
| vmadc.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmadc.vvm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vadc/1 |
| vmadc.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmadc.vxm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmadd.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/2 |
| vmadd.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vimul/2 |
| vmand.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmlogic/1 |
| vmandn.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmlogic/1 |
| vmax.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1 |
| vmax.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vialu/1 |
| vmaxu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1 |
| vmaxu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vialu/1 |
| vmerge.vim | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVISmith;RVVTS;SiFive RIF;libriscv | vmerge/1 |
| vmerge.vvm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmerge/1 |
| vmerge.vxm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmerge/1 |
| vmfeq.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmfeq.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmfge.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vfcmp/1 |
| vmfgt.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vfcmp/1 |
| vmfle.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmfle.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmflt.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmflt.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vfcmp/1 |
| vmfne.vf | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vfcmp/1 |
| vmfne.vv | REQUIRED | floating_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vfcmp/1 |
| vmin.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1 |
| vmin.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vialu/1 |
| vminu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1 |
| vminu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vialu/1 |
| vmnand.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmlogic/1 |
| vmnor.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;SiFive RIF | libriscv | vmlogic/1 |
| vmor.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmlogic/1 |
| vmorn.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmlogic/1 |
| vmsbc.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmsbc.vvm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vadc/1 |
| vmsbc.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmsbc.vxm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vmsbf.m | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmunary/1 |
| vmseq.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVISmith;SiFive RIF;libriscv | vicmp/1 |
| vmseq.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vicmp/1 |
| vmseq.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmsgt.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | libriscv | vicmp/1 |
| vmsgt.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF | vicmp/1 |
| vmsgtu.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | — | vicmp/1 |
| vmsgtu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vicmp/1 |
| vmsif.m | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmunary/1 |
| vmsle.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | libriscv | vicmp/1 |
| vmsle.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmsle.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vicmp/1 |
| vmsleu.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | — | vicmp/1 |
| vmsleu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vicmp/1 |
| vmsleu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmslt.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmslt.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmsltu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vicmp/1 |
| vmsltu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vicmp/1 |
| vmsne.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | libriscv | vicmp/1 |
| vmsne.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF | vicmp/1 |
| vmsne.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vicmp/1 |
| vmsof.m | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmunary/1 |
| vmul.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/2;vmul_vv/1 |
| vmul.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vimul/2 |
| vmulh.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/3 |
| vmulh.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vimul/3 |
| vmulhsu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/3 |
| vmulhsu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vimul/3 |
| vmulhu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vimul/3 |
| vmulhu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vimul/3 |
| vmv.s.x | REQUIRED | permutation | ACT;Ara;CHIPS | libriscv | vmvsx/1 |
| vmv.v.i | REQUIRED | integer_single_width | ACT;Ara;CHIPS | RVISmith;SiFive RIF;libriscv | vmerge/1 |
| vmv.v.v | REQUIRED | integer_single_width | ACT;Ara;CHIPS | SiFive RIF;libriscv | vmerge/1 |
| vmv.v.x | REQUIRED | integer_single_width | ACT;Ara;CHIPS;SiFive RIF | SiFive RIF;libriscv | vmerge/1 |
| vmv.x.s | REQUIRED | permutation | ACT;Ara;CHIPS | libriscv | vmvxs/1 |
| vmv1r.v | REQUIRED | whole_register_move | ACT;Ara;CHIPS;RVV-ATG | RVISmith;SiFive RIF;libriscv | vmvNr/1 |
| vmv2r.v | REQUIRED | whole_register_move | ACT;Ara;CHIPS;RVV-ATG | libriscv | vmvNr/1 |
| vmv4r.v | REQUIRED | whole_register_move | ACT;Ara;CHIPS;RVV-ATG | libriscv | vmvNr/1 |
| vmv8r.v | REQUIRED | whole_register_move | ACT;Ara;CHIPS;RVV-ATG | libriscv | vmvNr/1 |
| vmxnor.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vmlogic/1 |
| vmxor.mm | REQUIRED | mask_bits | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vmlogic/1 |
| vnclip.wi | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG | — | vnclip/1 |
| vnclip.wv | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;RVVTS | vnclip/1 |
| vnclip.wx | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vnclip/1 |
| vnclipu.wi | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG | — | vnclip/1 |
| vnclipu.wv | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vnclip/1 |
| vnclipu.wx | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vnclip/1 |
| vnmsac.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF | vimul/2 |
| vnmsac.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vimul/2 |
| vnmsub.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vimul/2 |
| vnmsub.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vimul/2 |
| vnsra.wi | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG | — | vnshift/1 |
| vnsra.wv | REQUIRED | integer_narrowing | ACT;CHIPS;RVV-ATG;SiFive RIF | — | vnshift/1 |
| vnsra.wx | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vnshift/1 |
| vnsrl.wi | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vnshift/1 |
| vnsrl.wv | REQUIRED | integer_narrowing | ACT;CHIPS;RVV-ATG;SiFive RIF | — | vnshift/1 |
| vnsrl.wx | REQUIRED | integer_narrowing | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vnshift/1 |
| vor.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | — | vialu/1 |
| vor.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;RVVTS;SiFive RIF;libriscv | vialu/1;vor_vv/1 |
| vor.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1 |
| vredand.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredmax.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredmaxu.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | RVISmith;SiFive RIF;libriscv | vred/1 |
| vredmin.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredminu.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredor.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredsum.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vredxor.vs | REQUIRED | integer_reduction | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vred/1 |
| vrem.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vimul/1 |
| vrem.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vimul/1 |
| vremu.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS | vimul/1 |
| vremu.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS;SiFive RIF | vimul/1 |
| vrgather.vi | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | — | vrgather/1 |
| vrgather.vv | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vrgather/1 |
| vrgather.vx | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | — | vrgather/1 |
| vrgatherei16.vv | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vrgather/1 |
| vrsub.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vialu/1 |
| vrsub.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vialu/1 |
| vs1r.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | RVISmith;SiFive RIF;libriscv | vsNr/1 |
| vs2r.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vsNr/1 |
| vs4r.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF;libriscv | vsNr/1 |
| vs8r.v | REQUIRED | whole_register_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vsNr/1 |
| vsadd.vi | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG | — | vsatadd/1 |
| vsadd.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vsadd.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vsaddu.vi | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG | — | vsatadd/1 |
| vsaddu.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vsaddu.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vsbc.vvm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vadc/1 |
| vsbc.vxm | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vadc/1 |
| vse16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vse/1 |
| vse32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vse/1 |
| vse64.v | REQUIRED | data_memory | ACT;Ara;CHIPS;SiFive RIF | RVISmith;SiFive RIF;libriscv | vse/1 |
| vse8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;SiFive RIF;libriscv | vse/1 |
| vsetivli | REQUIRED | configuration | Ara;CHIPS | RVISmith;libriscv | vsetivli/1 |
| vsetvl | REQUIRED | configuration | Ara;CHIPS | — | vsetvl/1 |
| vsetvli | REQUIRED | configuration | Ara;CHIPS | RVISmith;SiFive RIF;libriscv | vsetvli/1 |
| vsext.vf2 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vext/1 |
| vsext.vf4 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vext/1 |
| vsext.vf8 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vext/1 |
| vslide1down.vx | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vslide1up.vx | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vslidedown.vi | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vslidedown.vx | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vslideup.vi | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | libriscv | vslide/1 |
| vslideup.vx | REQUIRED | permutation | ACT;Ara;CHIPS;RVV-ATG | — | vslide/1 |
| vsll.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVISmith;libriscv | vialu/1;vsll_vi/1 |
| vsll.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vialu/1 |
| vsll.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vialu/1 |
| vsm.v | REQUIRED | mask_memory | ACT;Ara;CHIPS | RVISmith;SiFive RIF;libriscv | vsm/1 |
| vsmul.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsmul/1 |
| vsmul.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsmul/1 |
| vsoxei16.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | — | vsxei/1 |
| vsoxei32.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | libriscv | vsxei/1 |
| vsoxei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsxei/1 |
| vsoxei8.v | REQUIRED | indexed_memory | ACT;CHIPS;SiFive RIF | RVISmith | vsxei/1 |
| vsoxseg2ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg2ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg2ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg2ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg3ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg3ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg3ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg3ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg4ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg4ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg4ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg4ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg5ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg5ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg5ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg5ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg6ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg6ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg6ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg6ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg7ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg7ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg7ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg7ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg8ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg8ei32.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsoxseg8ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsoxseg8ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsra.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vialu/1 |
| vsra.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vialu/1 |
| vsra.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vialu/1 |
| vsrl.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG | libriscv | vialu/1;vsrl_vi/1 |
| vsrl.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vialu/1 |
| vsrl.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vialu/1 |
| vsse16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith | vsse/1 |
| vsse32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith;libriscv | vsse/1 |
| vsse64.v | REQUIRED | data_memory | ACT;Ara;CHIPS;SiFive RIF | RVISmith | vsse/1 |
| vsse8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vsse/1 |
| vsseg2e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg2e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vsseg/1 |
| vsseg2e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsseg2e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg3e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg3e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg3e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsseg3e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vsseg/1 |
| vsseg4e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vsseg/1 |
| vsseg4e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg4e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsseg4e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg5e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg5e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg5e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vsseg5e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg6e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg6e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg6e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vsseg6e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg7e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg7e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg7e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vsseg7e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg8e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg8e32.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsseg8e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsseg8e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | libriscv | vsseg/1 |
| vssra.vi | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG | — | vsshift/1 |
| vssra.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsshift/1 |
| vssra.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsshift/1 |
| vssrl.vi | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG | — | vsshift/1 |
| vssrl.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsshift/1 |
| vssrl.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsshift/1 |
| vssseg2e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg2e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg2e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vssseg2e8.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg3e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg3e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg3e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vssseg3e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg4e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg4e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg4e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vssseg4e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg5e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg5e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg5e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vssseg5e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg6e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg6e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg6e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vssseg6e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg7e16.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg7e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg7e64.v | REQUIRED | data_memory | ACT;CHIPS | — | vsseg/1 |
| vssseg7e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg8e16.v | REQUIRED | data_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg8e32.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssseg8e64.v | REQUIRED | data_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vssseg8e8.v | REQUIRED | data_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vssub.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vssub.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vssubu.vv | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vssubu.vx | REQUIRED | fixed_point | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vsatadd/1 |
| vsub.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1;vsub_vv/1 |
| vsub.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF | vialu/1 |
| vsuxei16.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVISmith | vsxei/1 |
| vsuxei32.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsxei/1 |
| vsuxei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsxei/1 |
| vsuxei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vsxei/1 |
| vsuxseg2ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg2ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg2ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg2ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsuxseg3ei16.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsuxseg3ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg3ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg3ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg4ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg4ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg4ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg4ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vsuxseg5ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg5ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg5ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg5ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg6ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg6ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg6ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg6ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg7ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg7ei32.v | REQUIRED | indexed_memory | ACT;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg7ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg7ei8.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg8ei16.v | REQUIRED | indexed_memory | ACT;CHIPS | — | vsseg/1 |
| vsuxseg8ei32.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS;RVV-ATG | — | vsseg/1 |
| vsuxseg8ei64.v | NOT_APPLICABLE | indexed_memory | — | — | vsseg/1 |
| vsuxseg8ei8.v | REQUIRED | indexed_memory | ACT;Ara;CHIPS | — | vsseg/1 |
| vwadd.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwadd.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vwint/1 |
| vwadd.wv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vwint/1 |
| vwadd.wx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vwint/1 |
| vwaddu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwaddu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwaddu.wv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vwint/1 |
| vwaddu.wx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmacc.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwmacc.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vwint/1 |
| vwmaccsu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwmaccsu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmaccu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG | RVVTS;libriscv | vwint/1 |
| vwmaccu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG | libriscv | vwint/1 |
| vwmaccus.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmul.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwmul.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmulsu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmulsu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwmulu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwmulu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vwint/1 |
| vwredsum.vs | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vwred/1 |
| vwredsumu.vs | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG | SiFive RIF | vwred/1 |
| vwsub.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsub.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsub.wv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsub.wx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsubu.vv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsubu.vx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | libriscv | vwint/1 |
| vwsubu.wv | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vwsubu.wx | REQUIRED | integer_widening | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vwint/1 |
| vxor.vi | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | — | vialu/1 |
| vxor.vv | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;SiFive RIF;libriscv | vialu/1;vxor_vv/1 |
| vxor.vx | REQUIRED | integer_single_width | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | SiFive RIF;libriscv | vialu/1 |
| vzext.vf2 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vext/1 |
| vzext.vf4 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS;libriscv | vext/1 |
| vzext.vf8 | REQUIRED | integer_extension | ACT;Ara;CHIPS;RVV-ATG;SiFive RIF | RVVTS | vext/1 |

## Recorded static implementation classes

Route/number identifies an exact saved class variant; operand forms can differ within one route.
These are literal saved classifications, not unconditional native-lowering or admission claims.
A helper entry can first attempt direct lowering. Direct QIR can use scalar lanes.
Refusal, guards, encoding, geometry and CPU predicates are outside this compact view.
Runtime status remains per form in the input/CSV; no runtime route is established here.

| Decoder route | Recorded direct QIR body | Recorded helper body |
|---|---|---|
| vadc/1 | PACKED_SIMD_CARRY | EXPLICIT_ELEMENT_REFERENCE |
| vadd_vi/1 | PACKED_SIMD_ADD | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vadd_vv/1 | PACKED_SIMD_ADD | UNMASKED_VSTART0_DISPATCH_CHUNK_SIMD_PLUS_ELEMENT_REMAINDER_OR_REF; RESTART_REF |
| vadd_vx/1 | PACKED_SIMD_ADD | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vand_vv/1 | PACKED_SIMD_ALU | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vavg/1 | PACKED_SIMD_ROUNDING | EXPLICIT_ELEMENT_REFERENCE |
| vcompress/1 | PACKED_SIMD_COMPRESS | EXPLICIT_ELEMENT_REFERENCE |
| vext/1 | PACKED_SIMD_EXTEND | EXPLICIT_ELEMENT_REFERENCE |
| vfalu/1 | PACKED_SIMD_FP | RVV_FAST_FALU_OR_FUSION_SIMD_PLUS_ELEMENT_REMAINDER; FP_REF_ON_REFUSAL |
| vfcmp/1 | PACKED_SIMD_FP_COMPARE | RVV_FAST_FCMP_SIMD_PLUS_ELEMENT_REMAINDER; FP_REF_ON_REFUSAL |
| vfcvt/1 | PACKED_SIMD_CONVERSION | EXPLICIT_ELEMENT_REFERENCE |
| vfma/1 | PACKED_SIMD_FP_FMA | RVV_FAST_FMA_SIMD_PLUS_ELEMENT_REMAINDER; FP_REF_ON_REFUSAL |
| vfmerge/1 | PACKED_SIMD_BIT_MOVE | EXPLICIT_ELEMENT_REFERENCE |
| vfmvfs/1 | SCALAR_ELEMENT_TRANSFER | EXPLICIT_ELEMENT_REFERENCE |
| vfmvsf/1 | SCALAR_ELEMENT_TRANSFER | EXPLICIT_ELEMENT_REFERENCE |
| vfred/1 | ORDERED_SCALAR_FP | EXPLICIT_ELEMENT_REFERENCE |
| vfunary1/1 | PACKED_SIMD_CLASSIFY | EXPLICIT_ELEMENT_REFERENCE |
| vfunary1/2 | DIRECT_ELEMENT_TABLE_ESTIMATE | EXPLICIT_ELEMENT_REFERENCE |
| vfunary1/3 | PACKED_SIMD_SQRT | EXPLICIT_ELEMENT_REFERENCE |
| vfwarith/1 | PACKED_SIMD_FP_WIDEN | EXPLICIT_ELEMENT_REFERENCE |
| vfwred/1 | ORDERED_SCALAR_FP | EXPLICIT_ELEMENT_REFERENCE |
| vialu/1 | PACKED_SIMD_ALU | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vicmp/1 | PACKED_SIMD_COMPARE | EXPLICIT_ELEMENT_REFERENCE |
| vid/1 | PACKED_SIMD_INDEX | EXPLICIT_ELEMENT_REFERENCE |
| vimul/1 | DIRECT_SCALAR_ACTIVE_LANES; NO_PACKED_INTEGER_DIVIDE | TRY_IMUL_REFUSES_THIS_DECODER_ROUTE_ENCODINGS; MULTIPLY_DIV_REM_REFERENCE |
| vimul/2 | PACKED_SIMD_EXCEPT_DIV_REM_AND_SEW64_HIGH_PRODUCT_SCALAR_LANES | TRY_IMUL_REFUSES_THIS_DECODER_ROUTE_ENCODINGS; MULTIPLY_DIV_REM_REFERENCE |
| vimul/3 | PACKED_FOR_SEW8_16_32; SCALAR_ACTIVE_LANES_FOR_SEW64 | TRY_IMUL_REFUSES_THIS_DECODER_ROUTE_ENCODINGS; MULTIPLY_DIV_REM_REFERENCE |
| vlNre/1 | BULK_SIMD_OR_NATIVE_ELEMENT_MEMORY | BULK_COPY_WITH_RESTART_PREFIX_AND_WRAP_RULES; COMPILER_VECTORIZATION_NOT_PROVEN |
| vle/1 | BULK_SIMD_OR_NATIVE_ELEMENT_MEMORY | UNMASKED_VSTART0_DISPATCH_CHUNK_SIMD_PLUS_REMAINDER_OR_REF; MASKED_OR_RESTART_REF |
| vleff/1 | HELPER_ONLY_FF | FIELD_ELEMENT_PERMISSION_PROBE_AND_LOAD; VL_TRIM_OR_TERMINAL_FAULT; NO_RECOVERABLE_GUEST_TRAP_PROOF |
| vlm/1 | BYTE_MEMORY_LOOP | EXPLICIT_ELEMENT_REFERENCE |
| vlse/1 | CONDITIONAL_GATHER_SIMD_OR_ELEMENT_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vlseg/1 | ELEMENT_FIELD_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vlxei/1 | ELEMENT_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vmaskpop/1 | WORD_POPCOUNT_OR_FIRST | REFERENCE_MASK_BIT_SCAN |
| vmerge/1 | PACKED_SIMD_SELECT_MOVE | EXPLICIT_ELEMENT_REFERENCE |
| vmlogic/1 | WORD_BITWISE | REFERENCE_MASK_BIT_LOOP |
| vmul_vv/1 | PACKED_SIMD_MULTIPLY | RVV_FAST_VMUL_VV_CASCADE_SIMD_PLUS_ELEMENT_REMAINDER; OTHER_MUL_DIV_REM_REF |
| vmunary/1 | WORD_PREFIX_OR_ELEMENT_IOTA | REFERENCE_PREFIX_OR_IOTA_ELEMENT_LOOP |
| vmvNr/1 | REGISTER_COPY | BULK_COPY_WITH_RESTART_PREFIX_AND_WRAP_RULES; COMPILER_VECTORIZATION_NOT_PROVEN |
| vmvsx/1 | SCALAR_ELEMENT_TRANSFER | EXPLICIT_ELEMENT_REFERENCE |
| vmvxs/1 | SCALAR_ELEMENT_TRANSFER | EXPLICIT_ELEMENT_REFERENCE |
| vnclip/1 | PACKED_SIMD_NARROW_CLIP | EXPLICIT_ELEMENT_REFERENCE |
| vnshift/1 | PACKED_SIMD_NARROW | EXPLICIT_ELEMENT_REFERENCE |
| vor_vv/1 | PACKED_SIMD_ALU | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vred/1 | PACKED_SIMD_REDUCTION | EXPLICIT_ELEMENT_REFERENCE |
| vrgather/1 | CONDITIONAL_GATHER_SIMD_OR_ELEMENT_PERMUTE | EXPLICIT_ELEMENT_REFERENCE |
| vsNr/1 | BULK_SIMD_OR_NATIVE_ELEMENT_MEMORY | BULK_COPY_WITH_RESTART_PREFIX_AND_WRAP_RULES; COMPILER_VECTORIZATION_NOT_PROVEN |
| vsatadd/1 | PACKED_SIMD_SATURATION | EXPLICIT_ELEMENT_REFERENCE |
| vse/1 | BULK_SIMD_OR_NATIVE_ELEMENT_MEMORY | UNMASKED_VSTART0_DISPATCH_CHUNK_SIMD_PLUS_REMAINDER_OR_REF; MASKED_OR_RESTART_REF |
| vsetivli/1 | SCALAR_CONFIGURATION | SCALAR_CONFIGURATION |
| vsetvl/1 | SCALAR_CONFIGURATION | SCALAR_CONFIGURATION |
| vsetvli/1 | SCALAR_CONFIGURATION | SCALAR_CONFIGURATION |
| vslide/1 | ELEMENT_PERMUTE | EXPLICIT_ELEMENT_REFERENCE |
| vsll_vi/1 | PACKED_SIMD_SHIFT | TRY_IALU_ALWAYS_REFUSES_SHIFT_CLASS; EXPLICIT_ELEMENT_REFERENCE |
| vsm/1 | BYTE_MEMORY_LOOP | EXPLICIT_ELEMENT_REFERENCE |
| vsmul/1 | PACKED_SIMD_EXCEPT_SEW64_SCALAR_LANES | EXPLICIT_ELEMENT_REFERENCE |
| vsrl_vi/1 | PACKED_SIMD_SHIFT | TRY_IALU_ALWAYS_REFUSES_SHIFT_CLASS; EXPLICIT_ELEMENT_REFERENCE |
| vsse/1 | ELEMENT_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vsseg/1 | ELEMENT_FIELD_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vsshift/1 | PACKED_SIMD_ROUNDING | EXPLICIT_ELEMENT_REFERENCE |
| vsub_vv/1 | PACKED_SIMD_ALU | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
| vsxei/1 | ELEMENT_MEMORY | EXPLICIT_ELEMENT_REFERENCE |
| vwint/1 | PACKED_SIMD_WIDEN | EXPLICIT_ELEMENT_REFERENCE |
| vwred/1 | PACKED_SIMD_REDUCTION | EXPLICIT_ELEMENT_REFERENCE |
| vxor_vv/1 | PACKED_SIMD_ALU | RVV_FAST_IALU_SIMD_OR_FUSION_PLUS_ELEMENT_REMAINDER; REF_ON_REFUSAL |
