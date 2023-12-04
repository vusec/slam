# Annotation definitions used by the scanner
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import angr
import claripy

class AttackerAnnotation(claripy.Annotation):
    """
    Attacker annotation
    """
    name : str
    chain_depth : dict
    simple_chain : bool

    def __init__(self, name : str, chain_depth : dict,
                 simple_chain : bool):
        self.name = name
        self.chain_depth = chain_depth
        self.simple_chain = simple_chain

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

class SecretAnnotation(claripy.Annotation):
    """
    Secret annotation
    """

    attacker_names : set
    chain_depth : dict
    simple_chain : bool


    def __init__(self, attacker_names : set, chain_depth : dict,
                 simple_chain : bool):
        self.attacker_names = attacker_names
        self.chain_depth = chain_depth
        self.simple_chain = simple_chain

    @property
    def eliminatable(self):
        return False

    @property
    def relocatable(self):
        return True

def init_state(state : angr.SimState):

    state.regs.gs = claripy.BVS('gs', 64)
    state.regs.rbp = claripy.BVS('rbp', 64)
    state.regs.r11 = claripy.BVS(f'rflags', 64)


    state.regs.rax = claripy.BVS(f'rax', 64, annotations=(AttackerAnnotation('rax', {'min': 0, 'max': 0}, True), ))
    state.regs.rbx = claripy.BVS(f'rbx', 64, annotations=(AttackerAnnotation('rbx', {'min': 0, 'max': 0}, True), ))
    state.regs.rcx = claripy.BVS(f'rcx', 64, annotations=(AttackerAnnotation('rcx', {'min': 0, 'max': 0}, True), ))
    state.regs.rdx = claripy.BVS(f'rdx', 64, annotations=(AttackerAnnotation('rdx', {'min': 0, 'max': 0}, True), ))
    state.regs.rsi = claripy.BVS(f'rsi', 64, annotations=(AttackerAnnotation('rsi', {'min': 0, 'max': 0}, True), ))
    state.regs.rdi = claripy.BVS(f'rdi', 64, annotations=(AttackerAnnotation('rdi', {'min': 0, 'max': 0}, True), ))
    state.regs.r8  = claripy.BVS(f'r8', 64, annotations=(AttackerAnnotation('r8', {'min': 0, 'max': 0}, True), ))
    state.regs.r9  = claripy.BVS(f'r9', 64, annotations=(AttackerAnnotation('r9', {'min': 0, 'max': 0}, True), ))
    state.regs.r10 = claripy.BVS(f'r10', 64, annotations=(AttackerAnnotation('r10', {'min': 0, 'max': 0}, True), ))
    state.regs.r11 = claripy.BVS(f'r11', 64, annotations=(AttackerAnnotation('r11', {'min': 0, 'max': 0}, True), ))
    state.regs.r12 = claripy.BVS(f'r12', 64, annotations=(AttackerAnnotation('r12', {'min': 0, 'max': 0}, True), ))
    state.regs.r13 = claripy.BVS(f'r13', 64, annotations=(AttackerAnnotation('r13', {'min': 0, 'max': 0}, True), ))
    state.regs.r14 = claripy.BVS(f'r14', 64, annotations=(AttackerAnnotation('r14', {'min': 0, 'max': 0}, True), ))
    state.regs.r15 = claripy.BVS(f'r15', 64, annotations=(AttackerAnnotation('r15', {'min': 0, 'max': 0}, True), ))
