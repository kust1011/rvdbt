set pagination off
set breakpoint pending on
handle SIGALRM nostop noprint pass
break trampoline_to_jit
commands
silent
printf "ENTRY state=%p vmem=%p code=%p rsp=%p\n",$rdi,$rsi,$rdx,$rsp
x/10gx $rsp
set $state=$rdi
set $tcode=$rdx
printf "ENTRY_GUEST_IP=%#x\n",*(unsigned*)($state+0xb8)
x/35i $rdx
continue
end
break qcgstub_trace_cache
commands
silent
printf "TRACE state=%p target=%#lx entry=%#lx rsp=%p ret=%p\n",$r13,$r14,$r15,$rsp,*(void**)$rsp
x/12gx $rsp
x/8i *(void**)$rsp
continue
end
break qcgstub_escape_link
commands
silent
printf "ESCAPE state=%p rsp=%p\n",$r13,$rsp
x/12gx $rsp
continue
end
run
info registers
p $_siginfo
info proc mappings
x/16i qcgstub_escape_link
x/32gx $rsp-64
x/30i $pc-40
bt
kill
