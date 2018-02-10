#!/usr/bin/env python

import argparse
import sys


def build_cli_parser(description="Red Canary example script"):
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument("--profile", type=str, action="store",
                        help="The credentials.response profile to use.")

    # File output
    parser.add_argument("--prefix", type=str, action="store",
                        help="Output filename prefix.")
    parser.add_argument("--append", type=str, action="store",
                        help="Append to output file.")

    # Time
    parser.add_argument("--days", type=int, action="store",
                        help="Number of days to search.")
    parser.add_argument("--minutes", type=int, action="store",
                        help="Number of days to search.")

    # Cb Response inputs
    cbr = parser.add_mutually_exclusive_group(required=False)
    cbr.add_argument("--queryfile", type=str, action="store",
                   help="File containing queries, one per line.")
    cbr.add_argument('--query', type=str, action="store",
                   help="A single Cb query to execute.")

    return parser


def convert_timestamp(datetime_obj):
    try:
        ret = datetime_obj.strftime('%Y%m%d-%H%M%S')
    except ValueError:
        ret = '00000000-000000'

    return ret


def log_err(msg):
    """Format msg as an ERROR and print to stderr.
    """
    msg = 'ERROR: {0}\n'.format(msg)
    sys.stderr.write(msg)


def log_info(msg):
    """Format msg and print to stdout.
    """
    msg = '{0}\n'.format(msg)
    sys.stdout.write(msg)
