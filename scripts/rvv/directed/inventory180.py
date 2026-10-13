#!/usr/bin/env python3
"""Keep 595 historical form pins; attach separate full179 P3 acceptance."""
import hashlib,json
from pathlib import Path
R=Path(__file__).resolve().parents[3];O=R/'docs/rvv-validation/directed-task180'
def read(p):return json.loads(p.read_text())
p=R/'docs/rvv-validation/directed-task175/PER_FORM_BATCH_BUILD_RESULT.json';m=read(p)
f=read(O/'FINAL_TOTALS.json');r=read(O/'RESTORED_ASSERTIONS_RESULT.json')
assert f['status']=='PASS_FINITE_FULL177_MATRIX_ON179_TRACE0' and f['cases_per_arm']==2418 and f['DUT_checks']==9672
assert r['returncode']==0 and r['all_four_assertions_restored'] and r['balanced_scratch_check_retained']
assert r['source_sha256']==hashlib.sha256((R/'dbt/qmc/qcg/rvv_vector_run_codegen_test.cpp').read_bytes()).hexdigest()
assert len(m['rows'])==595 and all(row[3]=='PASS_FINITE_SCOPE' for row in m['rows'])
assert m['accepted_after176']==595 and m['task176_final_evidence']['commit']=='481bfb56362952551be7367fc12d48abb198074b'
expected={'vfsqrt.v':24305,'vfrec7.v':59835,'vfrsqrt7.v':35810}
for row in m['rows']:
 if row[0] in expected:
  assert row[1]==176 and all(n==expected[row[0]] for n in row[5].values())
# Preserve all historical rows and the previous all-form NOT_RUN field.
assert m['final_common_build_validation']=='NOT_RUN'
m['scope_after180']=dict(per_form='595/595 finite historical forms; mixed actual build pins including accepted176',final179_P3='PASS_FINITE_FULL177_MATRIX_TRACE0',P3_candidate_sha256=f['candidate_sha256'],P3_receipt='docs/rvv-validation/directed-task180/FINAL_TOTALS.json',P3_cases_per_arm=2418,P3_DUT_checks=9672,new_form_credit=0,all_form_common179='NOT_RUN',external_common179='NOT_RUN',P4='Session3 moving to explicit179 namespace; historical174 results remain174')
p.write_text(json.dumps(m,separators=(',',':'))+'\n')
(O/'EXACT_GAPS_AFTER180.json').write_text(json.dumps(dict(required=595,accepted=595,gaps=[],scope=m['scope_after180'],restored_assertions='PASS',contract_suites=7,focused179_trace1='PASS_RETAINED;54 cases per DUT arm; no full trace1 claim',remaining=['all-form/external common179 outside Task180','full2418 trace1 not run','proof outside actual scanner subset and fault-return/repair/retry not supplied']),indent=2)+'\n')
print('595 historical forms including176; full179 P3 accepted separately, zero new form credit')
