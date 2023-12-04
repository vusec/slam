# Custom memory hooks
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import angr

from config import *
from helper import *
from annotations import *


class Hook:

    proj : angr.Project
    symbol_name : str
    entry_address : int

    def __init__(self, proj : angr.Project, symbol_name : str, entry_address : int):

        self.proj = proj
        self.symbol_name = symbol_name
        self.entry_address = entry_address

    def __output_translation(self, state : angr.SimState, translation_type, mem_address):

        # Get general information
        bbl_list = list(state.history.bbl_addrs)
        number_of_bb = len(bbl_list)
        number_of_instructions = self.__get_number_of_instructions(bbl_list, state.addr)

        if number_of_instructions > MAX_INSTRUCTIONS:
            return

        if mem_address.depth == 1 or (
            mem_address.depth == 2 and mem_address.op == '__add__'):
            simple_chain = True
        else:
            simple_chain = False


        # Get information from annotations

        attacker_names = set()
        chain_depth = {'min' : 9999999, 'max' : 0}

        for anno in mem_address.annotations:

            if not anno.simple_chain:
                simple_chain = False

            if isinstance(anno, SecretAnnotation):
                attacker_names.update(anno.attacker_names)

                if chain_depth['min'] > anno.chain_depth['min']:
                    chain_depth['min'] = anno.chain_depth['min']

                if chain_depth['max'] < anno.chain_depth['max']:
                    chain_depth['max'] = anno.chain_depth['max']

        # First info line

        output = ""
        output += f"[TRANSLATION] EntrySymbol: {self.symbol_name}; " \
                    f"EntryAddr:  {hex(self.entry_address)}; TransAddr: {hex(state.addr)}; " \
                    f"Type: {translation_type}; BBs: {number_of_bb}; INSTs: {number_of_instructions}; " \
                    f"Attacker: {sorted(list(attacker_names))}; " \
                    f"ChainDepthMin: {chain_depth['min']}; ChainDepthMax: {chain_depth['max']}; "\
                    f"SimpleTrans: {simple_chain}"
        output += "\n"


        # Get sub asts with secret and attacker annotations

        sub_ast_attacker = []
        sub_ast_secret = []

        if mem_address.depth > 1:

            for sub_ast in mem_address.args:

                attacker_anno = False
                secret_anno = False

                for anno in sub_ast.annotations:
                    if isinstance(anno, SecretAnnotation):
                        secret_anno = True
                    elif isinstance(anno, AttackerAnnotation):
                        attacker_anno = True

                if secret_anno:
                    sub_ast_secret.append(sub_ast)
                elif attacker_anno:
                    sub_ast_attacker.append(sub_ast)

        mem_address_str = str(mem_address)
        output += f"  - Memory Address AST: {mem_address_str if len(mem_address_str) < 200 else mem_address_str[:200] + '...' }\n"

        sub_ast_attacker_str = str(sub_ast_attacker)
        output += f"  - Attacker sub-ASTs : {sub_ast_attacker_str if len(sub_ast_attacker_str) < 200 else sub_ast_attacker_str[:200] + '...' }\n"

        sub_ast_secret_str = str(sub_ast_secret)
        output += f"  - Secret sub-ASTs   : {sub_ast_secret_str if len(sub_ast_secret_str) < 200 else sub_ast_secret_str[:200] + '...' }\n"

        # Output code path

        self.proj.kb.comments = {state.addr : "SECRET TRANSLATION"}

        block_output = ""

        for bbl_addr in bbl_list:

            block = self.proj.factory.block(bbl_addr)

            block_output += self.proj.analyses.Disassembly(ranges=[(block.addr, block.addr + block.size)]).render()
            block_output += "\n"

        output += block_output

        print(output)


    def mem_read_hook_after(self, state : angr.SimState):


        if DEBUG_MEM_READ:
            print("\n", "-"*20)
            print(f"MemReadHook After: {hex(state.addr)}")
            print(f"mem_read_address: {state.inspect.mem_read_address}")
            print(f"mem_read_expr: {state.inspect.mem_read_expr}")
            print(f"mem_read_expr anno: {state.inspect.mem_read_expr.annotations}")

        apply_child_annotations(state.inspect.mem_read_address)

        mem_read_address = state.inspect.mem_read_address

        if not mem_read_address.symbolic:
            return

        if mem_read_address.depth == 1 or (
            mem_read_address.depth == 2 and mem_read_address.op == '__add__'):
            simple_chain = True
        else:
            simple_chain = False


        is_attacker = False
        secret_translated = False

        attacker_names = set()
        chain_depth = {'min' : 9999999, 'max' : 0}

        for anno in mem_read_address.annotations:
            if isinstance(anno, AttackerAnnotation):
                is_attacker = True
                attacker_names.add(anno.name)

            elif isinstance(anno, SecretAnnotation):
                secret_translated = True
                attacker_names.update(anno.attacker_names)

            if chain_depth['min'] > anno.chain_depth['min']:
                chain_depth['min'] = anno.chain_depth['min']

            if chain_depth['max'] < anno.chain_depth['max']:
                chain_depth['max'] = anno.chain_depth['max']

            if not anno.simple_chain:
                simple_chain = False

        # Propagate annotations

        if is_attacker or secret_translated:

            chain_depth['min'] += 1
            chain_depth['max'] += 1

            # We do not annotate if we load annotated data
            if len(state.inspect.mem_read_expr.annotations) == 0:

                # We only consider 64-bit secret loads
                if state.inspect.mem_read_length == 8:
                    state.inspect.mem_read_expr = state.inspect.mem_read_expr.annotate(
                        SecretAnnotation(attacker_names, chain_depth, simple_chain))
                else:
                    for name in attacker_names:
                        state.inspect.mem_read_expr = state.inspect.mem_read_expr.annotate(
                            AttackerAnnotation(name, chain_depth, simple_chain))

        # Secret is translated

        if secret_translated:
            self.__output_translation(state, 'Load', mem_read_address)



    def mem_write_hook_before(self, state : angr.SimState):

        if DEBUG_MEM_READ:
            print(f"\nMemWrite After: {hex(state.addr)}")
            print(f"mem_write_address: {state.inspect.mem_write_address}")
            print(f"mem_write_address Anno: {state.inspect.mem_write_address.annotations}")
            print(f"mem_write_expr: {state.inspect.mem_write_expr}")

        apply_child_annotations(state.inspect.mem_write_address)

        mem_write_address = state.inspect.mem_write_address

        if not mem_write_address.symbolic:
            return

        secret_translated = False

        for anno in mem_write_address.annotations:
            if isinstance(anno, SecretAnnotation):
                secret_translated = True

        if secret_translated:
            self.__output_translation(state, 'Store', mem_write_address)




    def __get_number_of_instructions(self, bbl_list, translation_addr):


        number_of_instructions = 0

        for bbl_addr in bbl_list[:-1]:
            block = self.proj.factory.block(bbl_addr)

            number_of_instructions += block.instructions

        # Get instructions in last block
        block = self.proj.factory.block(bbl_list[-1])

        for instruction_addr in block.instruction_addrs:
            number_of_instructions += 1
            if instruction_addr == translation_addr:
                break

        return number_of_instructions






