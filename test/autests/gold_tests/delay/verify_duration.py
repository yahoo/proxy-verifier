#!/usr/bin/env python3
'''
Verify client output recorded an expected replay duration.
'''
# @file
#
# Copyright 2021, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import argparse
import sys
import re


def line_has_timing_data(line):
    """
    Determine whether the line has Verifier client timing data in it.

    >>> line_has_timing_data('   [0]: h2 is negotiated.')
    False
    >>> line_has_timing_data(' [1]: 2 transactions in 2 sessions (reuse 1) in 1790 milliseconds (0.1 / millisecond).')
    True
    >>> line_has_timing_data(r' [1]: 2 transactions in 2 sessions (reuse 1) in 1790 milliseconds (0.1 / millisecond).\\n')
    True
    """
    line_matcher = re.compile('.*transactions in .* sessions .* in .* milliseconds.*')
    return line_matcher.match(line) is not None

def get_replay_duration(line):
    """
    Retrieve the number of milliseconds the replay took.

    >>> get_replay_duration(' [1]: 2 transactions in 2 sessions (reuse 1) in 1790 milliseconds (0.1 / millisecond).')
    1790
    >>> get_replay_duration(r' [1]: 2 transactions in 2 sessions (reuse 1) in 1790 milliseconds (0.1 / millisecond).\\n')
    1790

    >>> get_replay_duration('   [0]: h2 is negotiated.')
    Traceback (most recent call last):
        ...
    ValueError: The line does not have timing data:
       [0]: h2 is negotiated.
    """
    if not line_has_timing_data(line):
        raise ValueError(f'The line does not have timing data:\n{line}')

    duration_getter = re.compile('in (\d+) milliseconds')
    return int(duration_getter.findall(line)[0])

def parse_args():
    parser = argparse.ArgumentParser(
            description='Verify client output recorded an expected replay duration.')

    parser.add_argument('client_output', type=argparse.FileType('r'),
                        help='The Verifier client output file.')

    parser.add_argument('min_milliseconds', type=int,
                        help='The minimum number of milliseconds the '
                        'replay should have taken.')

    return parser.parse_args()


def main():
    args = parse_args()

    min_milliseconds = args.min_milliseconds
    for line in args.client_output:
        if not line_has_timing_data(line):
            continue

        duration_in_ms = get_replay_duration(line)

        if duration_in_ms >= min_milliseconds:
            print(f'Good: replay took {duration_in_ms} ms which is more '
                  f'than required {min_milliseconds} ms')
            return 0
        else:
            print(f'Bad: replay took {duration_in_ms} ms which is less than '
                  f'than required {min_milliseconds} ms')
            return 1


if __name__ == '__main__':
    import doctest
    doctest.testmod()
    sys.exit(main())
