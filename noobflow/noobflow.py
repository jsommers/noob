#!/usr/bin/env python3

""" Work-in-Progress eBPF Flow Collecting Prototype """
#
# Nolan Rudolph
#
# Requirements:
#   1. Network Driver of the following devices:
#       a. bnxt
#       b. thunder
#       c. i40e
#       d. ixgbe
#       e. mlx4/mlx5
#       f. nfp
#       g. qede
#       h. tun
#       i. virtio_net

import bcc
from bcc import BPF
import ctypes
import argparse, logging
import os, sys, time
from socket import inet_ntoa, ntohl, ntohs
import ipaddress
from math import floor
from collections import Counter

# Global Variables #
CPU_COUNT = os.cpu_count()

def _sweep_flows(flows, offset, out_file):
    pktcounts = Counter()
    logging.info("sweep flows")
    now = time.time()
    with open(out_file, "a") as outfile:
        for flowattr, accum in flows.items():
            # accumulate flow counters over all CPUs
            n_packets = 0
            n_bytes = 0
            start = 0
            end = 0
            for j in range(0, CPU_COUNT):
                flowaccum = accum[j]
                pktcounts[f"CPU{j}"] += flowaccum.packets
                n_packets += flowaccum.packets
                n_bytes += flowaccum.bytes
                if start == 0:
                    start = flowaccum.start
                elif flowaccum.start > 0:
                    start = min(start, flowaccum.start)
                end = max(end, flowaccum.end)
            start = start/1e9 + offset # convert to unix time
            end = end/1e9 + offset  # convert to unix time

            l2_proto = flowattr.l2_proto
            l4_proto = flowattr.l4_proto
            src_ip = ""
            dst_ip = ""

            # Parse IP addresses according to ethertype (EIP4 / EIP6)
            if l2_proto == 0x0800:
                src_ip = ipaddress.ip_address(ntohl(flowattr.src_ip))
                dst_ip = ipaddress.ip_address(ntohl(flowattr.dst_ip))
            elif l2_proto == 0x8100:
                src_ip = ipaddress.ipv6_address(ntohl(flowattr.src_ip))
                dst_ip = ipaddress.ipv6_address(ntohl(flowattr.dst_ip))

            # Port requires little endian conversion
            src_p = ntohs(flowattr.src_port)
            dst_p = ntohs(flowattr.dst_port)

            line = "{},{},{},{},{},{},{},{},{},{}".format(start, end, 
                src_ip, dst_ip, src_p, dst_p, hex(l2_proto), 
                l4_proto, n_packets, n_bytes)
            print(line, file=outfile)
    flows.clear()
    return pktcounts


# Main #
def main(args):
    with open('/proc/uptime') as inf:
        uptime = float(inf.read().split()[0])
    offset = time.time() - uptime

    # User argument handling
    loglevel = logging.INFO
    run_time = 3600
    out_file = "flows.csv"
    if args.debug:
        loglevel = logging.DEBUG
    if args.runtime:
        run_time = args.runtime
    if args.output:
        out_file = args.output

    # Logger stuff
    logging.basicConfig(level=loglevel, 
                        format="[%(levelname)s] %(name)s : %(message)s")

    # Retrieve user arguments
    IF = args.interface
    logging.info("Using interface %s" % IF)

    # CFlags for eBPF compile
    _cflags = ["-DMAPSIZE={}".format(args.mapsize)]
    if args.xdpaction == 'drop':
        _cflags.append('-DXDPACTION=XDP_DROP')
    else:
        _cflags.append('-DXDPACTION=XDP_PASS')

    # Compile and load the required source C file
    logging.debug("Loading noobflow.c...")
    bpf = BPF(src_file="noobflow.c", \
              cflags=_cflags, \
              debug=bcc.DEBUG_SOURCE | bcc.DEBUG_BPF)

    # Get the main function
    logging.debug("Loading function xdp_parser()...")
    fn = bpf.load_func("xdp_parser", BPF.XDP)

    # Attach the flow collector
    logging.debug("Attaching xdp_parser() to kernel hook...")
    bpf.attach_xdp(IF, fn, 0)

    flow_store_fun = {}
    null_handler = bpf.load_func("null_parser", bpf.XDP)
    for idx in [0,1]:
        v4fn = bpf.load_func(f"parse_ipv4_flows{idx}", bpf.XDP)
        v6fn = bpf.load_func(f"parse_ipv6_flows{idx}", bpf.XDP)
        flow_store_fun[idx] = {4: v4fn, 6: v4fn}
    prog_array = bpf.get_table("parse_layer3")
    _set_flow_buffer(prog_array, flow_store_fun, 0)

    # list of two tables that we swap back and forth with
    # a la double buffering
    flowtables = [bpf.get_table('flows0'), bpf.get_table('flows1')]

    # 'time_wizard' holds epoch time of first flow from XDP
    # 'py_start' holds epoch time of something else, but only matters for while loop
    py_start = time.time()

    # Main flow collecting segment (Garbage Collector)
    logging.info("*** COLLECTING FOR %ss ***" % run_time)

    curr_buffer = 0
    allcounts = Counter()
    try:
        while abs(time.time() - py_start) < run_time:
            logging.debug("*** COLLECTING FOR %ss ***" % floor(run_time - (time.time() - py_start)))
            time.sleep(args.swap)
            next_buffer = (curr_buffer + 1) % 2
            logging.info(f"Swapping to buffer {next_buffer}")
            _set_flow_buffer(prog_array, flow_store_fun, next_buffer)
            counts = _sweep_flows(flowtables[curr_buffer], offset, out_file)
            allcounts += counts
            curr_buffer = next_buffer
    except KeyboardInterrupt:
        logging.info("Caught ctrl+c; finishing")

    # set jump table so that flow capture stops
    logging.info("Stopping flow collection.")
    for af in [4,6]:
        prog_array[ctypes.c_int(af)] = ctypes.c_int(null_handler.fd)

    # clear out any flows
    logging.info("Clearing any remaining flows.")
    for i in range(2):
        _sweep_flows(flowtables[i], offset, 0, out_file)

    bpf.remove_xdp(IF, 0)
    logging.info("Removed XDP Program from Kernel.")

    with open(out_file, "a") as outfile:
        allcount = sum(allcounts.values())
        cts = ' '.join([ f"{cpu}:{ct}" for cpu,ct in allcounts.most_common() ])
        print(allcount, cts)
        print("#", allcount, cts, file=outfile)

    logging.info("Finished!")


def _set_flow_buffer(prog_array, fnmap, idx):
    '''
    change flow storage handler functions to use either
    flows0 or flows1 storage maps.  eBPF does this
    atomically, on the fly.  
    '''
    funs = fnmap[idx]
    for af,handler in funs.items():
        prog_array[ctypes.c_int(af)] = ctypes.c_int(handler.fd)
    

# Argparse and Main Call #
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mapsize", default=1048576, type=int,
                        help="Size of BPF flow storage maps")
    parser.add_argument("-x", "--xdpaction", default="drop", 
                        choices=('drop','pass'),
                        help='Action to take with packets after flow recording')
    parser.add_argument("-i", "--interface", required=True, type=str,
                        help="Specify which interface to listen for packets on")
    parser.add_argument("-s", "--swap", default=5, required=False, type=int, 
                        help="Amount of time between flow buffer/map swaps")
    parser.add_argument("-t", "--runtime", default=3600, required=False, type=int, 
                        help="Time to run (s) [default = run until ctrl+c]")
    parser.add_argument("-o", "--output", default="flows.csv", required=False, type=str,
                        help="Name of file to output flows in CSV format")
    parser.add_argument("-d", "--debug", default=False, required=False, action="store_true",
                        help="Allow debug logging")
    args = parser.parse_args()
    main(args)
