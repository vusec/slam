# Script to convert the log output to a sqlite3 database
#
# Date: November 23, 2023
# Author: Sander Wiebing - Vrije Universiteit Amsterdam

import argparse
import pandas as pd
import sqlite3

def parse_translation_file(input_file):
    # Log line ->
    # [TRANSLATION] EntrySymbol: XXX; EntryAddr:  XXX; TransAddr: XXX;
    # Type: XXX; BBs: XXX; INSTs: XXX; Attacker: ['XXX', 'XXX']; ChainDepthMin:
    # XXX; ChainDepthMax: XXX; SimpleTrans: XXX

    invalid_lines = 0

    data = []

    with open(input_file) as f:

        for line in f:
            fields = line.strip().split(';')


            if len(fields) != 10:
                invalid_lines += 1
                continue

            # Strip values from fields
            v = []
            for f in fields:
                # simple hack for list
                v.append(f.rsplit(sep=":", maxsplit=1)[1].removesuffix(";").strip())


            try:

                data.append({'label' : v[0], 'entry_addr' : v[1],
                        'translation_addr' : v[2], 'type' : v[3],
                        "number_of_bbs" : int(v[4]),
                        "number_of_insts" : int(v[5]),
                        "attacker_registers" : v[6],
                        "chain_depth_min" : int(v[7]),
                        "chain_depth_max" : int(v[8]),
                        "simple_trans" : v[9].lower() == 'true',
                        })

            except:
                invalid_lines += 1
                continue

    print("Number of invalid lines:", invalid_lines)

    return pd.DataFrame(data)

def main(input_file, db_file):

    df = parse_translation_file(input_file)

    conn = sqlite3.connect(db_file)
    df.to_sql("translations", conn, if_exists='replace', index=False)
    conn.close()





if __name__ == '__main__':

    arg_parser = argparse.ArgumentParser(description='Convert Translation log to SQL Database')

    arg_parser.add_argument('input_file')

    arg_parser.add_argument('db_file')

    args = arg_parser.parse_args()

    main(args.input_file, args.db_file)
