#!/bin/bash

# riscv-test dir
# modified from https://github.com/WangHanChi/riscv-atom/blob/M-extension/scripts/riscv-test.sh

RED="\e[31m"
GREEN="\e[32m"
ORANGE="\e[33m"
CYAN="\e[36m"
NOCOLOR="\e[0m"

if (( $# > 1 )); then
    echo "Usage: $0 [build-directory] (SPIKE selects the Spike executable)" >&2
    exit 2
fi
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd) || exit 1
build_dir=${1:-build-llvm-19}
case "$build_dir" in
    /*) ;;
    *) build_dir="$repo_dir/$build_dir" ;;
esac
input_dir="$repo_dir/riscv-tests/isa"
if [[ ! -d "$build_dir" || ! -f "$build_dir/bin/elfrun" || ! -x "$build_dir/bin/elfrun" ]]; then
    echo "Missing build directory or executable elfrun: $build_dir" >&2
    exit 1
fi
if ! spike=$(command -v -- "${SPIKE:-spike}") || [[ ! -f "$spike" || ! -x "$spike" ]]; then
    echo "Missing executable Spike: ${SPIKE:-spike}" >&2
    exit 1
fi
case "$spike" in
    /*) ;;
    *) spike="$PWD/$spike" ;;
esac
cd -- "$build_dir" || exit 1
mkdir -p -- troot tcache || exit 1

# This checks successful exits only, not architectural-state equivalence.
run_case() {
    local guest=$1
    local input="$input_dir/$guest"
    local spike_result elfrun_result
    if [[ ! -f "$input" || ! -r "$input" ]]; then
        echo "Missing or unreadable input: $input" >&2
        return 1
    fi
    cp -- "$input" troot/ || return 1
    "$spike" --isa=RV32IM "troot/$guest"
    spike_result=$?
    echo "Spike result: $spike_result"
    ./bin/elfrun --fsroot troot --cache tcache --logs dbt -- "$guest"
    elfrun_result=$?
    echo "Elfrun result: $elfrun_result"
    if (( spike_result == 0 && elfrun_result == 0 )); then
        echo -e "${GREEN}Both exit-status checks passed${NOCOLOR}"
        return 0
    fi
    echo -e "${RED}Exit-status check failed${NOCOLOR}" >&2
    return 1
}

declare -a isa_RV32UI_p=( "add" "addi" "and" "andi" "auipc" "beq" "bge" "bgeu" "blt" "bltu" "bne" "jal" "jalr" "lb" "lbu" "lh" "lhu" "lui" "lw" "or" 
 "ori" "sb" "sh" "sll" "simple" "slli" "slt" "slti" "sltiu" "sltu" "sra" "srai" "srl" "srli" "sub" "sw" "xor" "xori" )

declare -a isa_RV32UM_p=( "div" "divu" "mul" "mulh" "mulhu" "mulhsu" "rem" "remu")

suss_rv32ui=0
fail_rv32ui=0
total_rv32ui=0

suss_rv32um=0
fail_rv32um=0
total_rv32um=0

echo "Now test rv32ui for RVDBT!!"
for isa_RV32UI in "${isa_RV32UI_p[@]}"
do
    echo testing instruction ${isa_RV32UI}
    if run_case "rv32ui-p-${isa_RV32UI}"
    then 
        suss_rv32ui=$(($suss_rv32ui+1))
    else 
        fail_rv32ui=$(($fail_rv32ui+1))
    fi
    total_rv32ui=$(($total_rv32ui+1))
    echo
done

echo

echo "Now test rv32um for RVDBT!!"
for isa_RV32UM in "${isa_RV32UM_p[@]}"
do
    echo testing instruction ${isa_RV32UM}
    if run_case "rv32um-p-${isa_RV32UM}"
    then 
        suss_rv32um=$(($suss_rv32um+1))
    else 
        fail_rv32um=$(($fail_rv32um+1))
    fi
    total_rv32um=$(($total_rv32um+1))
    echo
done

echo "=============================="
echo "rv32ui-p instruction set :"
echo -e "${NOCOLOR}The pass rate is ${GREEN}$suss_rv32ui/$total_rv32ui"
echo -e "${NOCOLOR}The fail rate is ${RED}$fail_rv32ui/$total_rv32ui${NOCOLOR}"
if [ $fail_rv32ui == "0" ]
then 
    echo -e "${CYAN}Pass rv32ui-p testing! ${NOCOLOR}"
else
    echo -e "${CYAN}Fail rv32ui-p testing! ${NOCOLOR}"
fi    
echo "=============================="
echo "rv32um-p instruction set :"
echo -e "${NOCOLOR}The pass rate is ${GREEN}$suss_rv32um/$total_rv32um"
echo -e "${NOCOLOR}The fail rate is ${RED}$fail_rv32um/$total_rv32um${NOCOLOR}"
if [ $fail_rv32um == "0" ]
then 
    echo -e "${CYAN}Pass rv32um-p testing! ${NOCOLOR}"
else
    echo -e "${CYAN}Fail rv32um-p testing! ${NOCOLOR}"
fi
echo "=============================="

(( fail_rv32ui == 0 && fail_rv32um == 0 ))
