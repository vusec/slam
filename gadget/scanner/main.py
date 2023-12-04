# Unmasked gadget scanner to find gadgets exploitable with SLAM
# (Spectre based on Linear Address Masking).
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import argparse

import angr
import claripy

from helper import *
from config import *
from hooks import *
from annotations import *
from explore_filter import *
from concretization import SimConcretizationStrategyAnyInBounds

def analyze_symbol(proj : angr.Project, entry_address, symbol_name):

    state = proj.factory.blank_state(addr=entry_address,
                    add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                 angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    state.solver._solver.timeout=SOLVER_TIMEOUT

    # We first try to use any_in_bounds, to prevent memory to be split-up at memory regions boundaries
    concretization_any_in_bounds = SimConcretizationStrategyAnyInBounds(0x1000000, 0xffffffff80000000)
    concretization_any = angr.concretization_strategies.any.SimConcretizationStrategyAny()

    state.memory.write_strategies = [concretization_any_in_bounds, concretization_any]
    state.memory.read_strategies = [concretization_any_in_bounds, concretization_any]

    # Init the hooks and state
    hooks = Hook(proj, symbol_name, entry_address)

    state.inspect.b('mem_read', when=angr.BP_AFTER, action=hooks.mem_read_hook_after)
    state.inspect.b('mem_write', when=angr.BP_BEFORE,action=hooks.mem_write_hook_before)

    init_state(state)

    # Explore
    sm = proj.factory.simgr(state)

    explore_filter = ExploreFilter(proj)

    sm.explore(filter_func=explore_filter.to_prune, avoid=[0])



def main(binary_file, do_pickle, symbol_name, entry_address):


    proj = load_angr_project(binary_file, do_pickle)
    remove_memory_sections(proj)

    # Analyze each symbol

    print(f"[INFO] Analyzing - Name: {symbol_name} Addr: {hex(entry_address)}")

    analyze_symbol(proj, entry_address, symbol_name)




if __name__ == '__main__':

    arg_parser = argparse.ArgumentParser(description='SLAM Unmasked Gadget Finder')

    arg_parser.add_argument('binary_file')

    arg_parser.add_argument("-p", '--pickle-project', action='store_true')

    arg_parser.add_argument('-n', '--gadget-name', default="gadget")
    arg_parser.add_argument('-a', '--gadget-address', required=True)

    args = arg_parser.parse_args()

    main(args.binary_file, args.pickle_project, args.gadget_name, int(args.gadget_address, 16))
