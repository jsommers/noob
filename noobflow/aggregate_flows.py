#!/usr/bin/env python3

import argparse
import csv

def main(infile, aggtime, outfile):
    done = {}
    flowhash = {}
    with open(infile) as infile:
        for line in infile:
            if line.startswith('#'):
                continue
            data = line.strip().split(',')
            flowkey = tuple(data[2:8])
            fdata = list(map(float, data[0:2])) + list(map(int, data[-2:]))
            if flowkey in flowhash:
                existing = flowhash[flowkey]
                if fdata[0] - existing[1] < aggtime:
                    existing[0] = min(existing[0], fdata[0])                    
                    existing[1] = max(existing[1], fdata[1])
                    existing[2] += fdata[2]
                    existing[3] += fdata[3]
                else:
                    done[flowkey] = existing
                    flowhash[flowkey] = fdata
            else:
                flowhash[flowkey] = fdata

    with open(outfile, 'w') as outf:
        _write_flows(outf, done)
        _write_flows(outf, flowhash)


def _write_flows(outf, fhash):
    for fkey,fdata in fhash.items():
        outdata = list(map(str, fdata[:2])) + list(fkey) + list(map(str, fdata[2:]))
        print(','.join(outdata), file=outf)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--outfile', default='aggflows.csv', help='Aggregated flows output file')
    parser.add_argument("-a", "--aggregate", default=60, required=False, type=int,
                        help="Aggregation time (s) to close flows [default = 60]")
    parser.add_argument('files', type=str, nargs='+', help='Input files to process')
    args = parser.parse_args()
    for f in args.files:
        main(f, args.aggregate, args.outfile)
