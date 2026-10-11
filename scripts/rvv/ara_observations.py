import re
def observations(raw):
 text=raw.decode(errors='replace')
 def arr(pattern):return[list(map(int,m))for m in re.findall(pattern,text)]
 def one(pattern):
  m=re.search(pattern,text);return list(map(int,m.groups()))if m else None
 return dict(vsets=arr(r'ARA_VSET line=(\d+) avl=(\d+) vl=(\d+) vtype=(\d+)'),assertions=arr(r'ARA_ASSERT id=(\d+) elements=(\d+) bytes=(\d+) vl=(\d+) vtype=(\d+) comparisons=(\d+) completed=(\d+)'),summary=one(r'ARA_SUMMARY status=(\d+) vsets=(\d+) assertions=(\d+) comparisons=(\d+)'),flags=arr(r'ARA_FLAG id=(\d+) line=(\d+) read_line=(\d+) read_pc=(\d+) checker_pc=(\d+) actual_lo=(\d+) actual_hi=(\d+) expected_lo=(\d+) expected_hi=(\d+) compared=(\d+) completed=(\d+)'),flag_summary=one(r'ARA_FLAG_SUMMARY reads=(\d+) flags=(\d+) completed=(\d+) comparisons=(\d+)'),scalars=arr(r'ARA_SCALAR id=(\d+) line=(\d+) checker_pc=(\d+) vl=(\d+) vtype=(\d+) actual_lo=(\d+) actual_hi=(\d+) expected_lo=(\d+) expected_hi=(\d+) compared=(\d+) completed=(\d+) sequence=(\d+)'),scalar_summary=one(r'ARA_SCALAR_SUMMARY scalars=(\d+) completed=(\d+) comparisons=(\d+)'))
