# General helper functions
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import pickle

import angr
import claripy

def load_angr_project(binary_file : str, do_pickle):

    if do_pickle:
        pickle_file = binary_file + '.angr'

        try:
            f = open(pickle_file, "rb")
            proj = pickle.load(f)
        except:
            proj = angr.Project(binary_file, auto_load_libs=False)
            f = open(pickle_file, "wb")
            pickle.dump(proj, f)
            f.close()
    else:
        proj = angr.Project(binary_file, auto_load_libs=False)


    return proj


def remove_memory_sections(proj : angr.Project):
    # We always remove remove the writeable segments to prevent
    # initialized concrete values (zeros) while they should be symbolic.

    # Get the start addresses of segments to remove
    start_addresses = []

    for segment in proj.loader.main_object.segments:

        if segment.is_writable:
            start_addresses.append(segment.min_addr)

    # Remove segment backers
    # NOTE: This works for the Linux kernel binary, not certain if it works
    # for all other binaries

    for addr in start_addresses:

        for start, backer in proj.loader.memory._backers:

            if addr >= start and addr < backer.max_addr:
                backer.remove_backer(addr)
                break



def apply_child_annotations(ast : claripy.BV):

    if ast.depth > 1:
        own_annotations = ast.annotations

        for sub_ast in ast.args:

            if not isinstance(sub_ast, claripy.ast.base.Base):
                continue

            apply_child_annotations(sub_ast)

            for anno in sub_ast.annotations:
                if anno not in own_annotations:
                    ast.annotations += (anno, )
