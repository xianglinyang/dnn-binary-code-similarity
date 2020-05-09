#!/usr/bin/env python
# coding:utf-8
import subprocess
import angr
import os
import pickle
import IPython

from tools.image import Image
from tools.util.asm import is_jump
from tools.util.log import logging

import NumericFeatureExtractor

log = logging.getLogger(__name__)
logging.getLogger('angr').setLevel('WARNING')
logging.getLogger('claripy').setLevel('WARNING')


def test():
    debug_vmlinux = "/home/xianglin/PycharmProjects/genius/testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    # debug_vmlinux="../testcase/x86_add"
    # debug_vmlinux = "/home/xianglin/Graduation/executables/x64_a"
    img = Image(debug_vmlinux)
    func_name = "dccp_rcv_state_process"
    # func_name = "main"
    entry_base = img.get_symbol_addr(func_name)
    if not entry_base:
        return
    func_cfg = img.get_cfg(func_name)
    func_cfg.normalize()
    all_nodes = []
    for n in func_cfg.nodes():
        if n.function_address == entry_base:
            all_nodes.append(n)
    #import IPython
    #IPython.embed()
    all_nodes.sort(key=lambda CFGNodeA: CFGNodeA.addr)
    for n in all_nodes:
        n.block.pp()
    #print(all_nodes))




if __name__ == "__main__":
    import sys
    ls = test()

    print(1)
