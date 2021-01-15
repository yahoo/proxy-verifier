#!/usr/bin/env python3
'''
Verify that one file is contained in another
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import argparse
import sys


def parse_args():
    parser = argparse.ArgumentParser(
            description='Verify the contents of one file are in another.')

    parser.add_argument('needle_file',
                        help='Determine whether needle_file is in haystack_file')

    parser.add_argument('haystack_file',
                        help='Determine whether needle_file is in haystack_file')

    return parser.parse_args()


def main():
    args = parse_args()

    needle_content = open(args.needle_file, 'r').read()
    haystack_content = open(args.haystack_file, 'r').read()

    if needle_content in haystack_content:
        print(f'Good: {args.needle_file} is in {args.haystack_file}')
        return 0
    else:
        print(f'Bad: {args.needle_file} is not in {args.haystack_file}')
        return 1


if __name__ == '__main__':
    sys.exit(main())
