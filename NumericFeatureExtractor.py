#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
import numpy as np
from tools.image import Image
from tools.util.asm import is_jump

"""
it is based on ARM64 instruction set, might add more CPU arch in the future
"""
######################################################################
# numeric feature
######################################################################
def get_consts(img, insn, offset):
    """
    get const from an instruction
    if op is in call function, pass
    else:   if it is an imm, check if it is an addr or numeric
            else [mem]

    Args:
        insn:(capstone.insn) an instuction
        offset(int): the i-th operand

    Returns:
        string_consts(list):
        numeric_consts(list):
    """
    string_consts = []
    numeric_consts = []
    insn = insn.insn
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    op_imm = {'ARM_OP_IMM', 'ARM64_OP_IMM', 'X86_OP_IMM', 'MIPS_OP_IMM'}
    op_mnemonic = insn.mnemonic
    # if mnemonic is in call functions, return
    if check_type(op_mnemonic, arm64_CI):
        return string_consts, numeric_consts

    base_pointer = {'pc'}
    operand = insn.operands[offset]
    op_type = operand.type
    # if it is an immediate value, output the value
    # contingent across all arch
    if op_type == capstone.arm64.ARM64_OP_IMM:
        # if adr, then string/numeric?, else numeric
        if check_type(op_mnemonic, {'adr'}):
            # turn int to addr hex
            bvv = claripy.BVV(operand.value.imm, 64)
            addr = bvv.args[0]
            string_const = get_string(img, addr)
            if string_const is None:
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)
            else:
                string_consts.append(string_const)
        else:
            numeric_consts.append(operand.value.imm)
    # [mem]
    elif op_type == capstone.arm64.ARM64_OP_MEM:
        if operand.value.mem.base != 0:
            base_reg = insn.reg_name(operand.value.mem.base)
            if base_reg in base_pointer:
                disp = operand.value.mem.disp
                addr = insn.address + disp
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)

    return string_consts, numeric_consts


def get_BB_consts(img, block):
    """
    get string and numeric consts from a block
    Args:
        img(tools.image.Image)
        block: angr.block

    Returns:
        string_consts(list): string consts from a block
        numeric_consts(list): numeric consts from a block

    """
    string_consts = []
    numeric_consts = []
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        num_operands = len(insn.operands)
        for offset in range(num_operands):
            strings, numerics = get_consts(img, insn, offset)
            string_consts += strings
            numeric_consts += numerics

    return string_consts, numeric_consts


def cal_insts(block):
    """calculate the number of instructions in a block"""
    return block.instructions


def cal_transfer_insts(block):
    arm_TI = {'mvn', "mov"}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm_TI):
            num = num + 1
    return num


def cal_call_insts(block):
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_CI):
            num = num + 1
    return num


def cal_arithmetic_insts(block):
    arm64_AI = {'add', 'sub', 'adc', 'sbc'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_AI):
            num = num + 1
    return num


def get_BB_features(img, block):
    """get block attributes, without offspring"""
    fea = []
    strings, consts = get_BB_consts(img, block)
    # 1 strings const
    fea.append(len(strings))
    # 2 numeric const
    fea.append(len(consts))
    # 3 transfer inst
    tran = cal_transfer_insts(block)
    fea.append(tran)
    # 4 calls
    calls = cal_call_insts(block)
    fea.append(calls)
    # 5 inst
    insts = cal_insts(block)
    fea.append(insts)
    # 6 arithmetic
    arti = cal_arithmetic_insts(block)
    fea.append(arti)
    # 7 offspring

    return fea


def get_func_fea(bin, func_name):
    
    node_num = 0

    img = Image(bin)

    entry_base = img.get_symbol_addr(func_name)
    if not entry_base:
        return
    func_cfg = img.get_cfg(func_name)
    func_cfg.normalize()
    all_nodes = []
    for n in func_cfg.nodes():
        if n.function_address == entry_base:
            all_nodes.append(n)
            node_num = node_num + 1
    all_nodes.sort(key=lambda CFGNodeA: CFGNodeA.addr)

    X_input = np.zeros((node_num, 7))
    node_mask = np.zeros((node_num, node_num))

    for u in range(len(all_nodes)):
        fea = get_BB_features(img, all_nodes[u].block)
        offs = 0
        for succ in all_nodes[u].successors:
            if succ.function_address == entry_base:
                offs += 1
                succ_index = all_nodes.index(succ)
                node_mask[u, succ_index] = 1
        fea.append(offs)
        X_input[u, :] = np.array(fea)

    return X_input, node_mask


######################################################################
# other functions
######################################################################
def check_type(t, t_set):
    """
    Args:
        t(str): operator or register
        t_set(set): check type set

    Returns:
        states(boolean): true if t is in t_set

    """
    for t_type in t_set:
        if t.startswith(t_type):
            return True
    return False


def get_string(img, addr):
    string = ""
    for i in range(1000):
        c = img.project.loader.memory.load(addr + i, 1)
        if ord(c) == 0:
            break
        elif 40 <= ord(c) < 128:
            string += chr(ord(c))
        else:
            return None
    return string


def get_numeric(img, addr):
    b = img.project.loader.memory.load(addr, 4)
    num = int.from_bytes(b, "little")
    return num


if __name__ == "__main__":
    bin = "/home/xianglin/PycharmProjects/genius/testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    func_name = "dccp_rcv_state_process"
    i, j = get_func_fea(bin, func_name)
