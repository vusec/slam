# Prune filter used by the scanner
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import angr

from config import *

class ExploreFilter():

    proj : angr.Project
    bb_instructions : dict


    def __init__(self, proj : angr.Project):

        self.proj = proj
        self.bb_instructions = {}


    def to_prune(self, state : angr.SimState):

        number_of_instructions = 0

        bbl_list = list(state.history.bbl_addrs)

        for bbl_addr in bbl_list:

            if bbl_addr not in self.bb_instructions:
                block = self.proj.factory.block(bbl_addr)

                # Creating a Capstone block is expensive, thus we
                # cache the result
                self.bb_instructions[bbl_addr] = block.instructions

            number_of_instructions += self.bb_instructions[bbl_addr]


        if number_of_instructions >= MAX_INSTRUCTIONS:
            return "pruned"

        else:
            return "active"
