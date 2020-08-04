#!/usr/bin/env python3

# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import ipaddress
import re
import sys
from urllib.parse import urlparse


description = \
    'Process a Traffic Server remap.config file and ' \
    'produce a URL input file for replay_gen.py'


def parse_remap_url(url):
    """
    Parse the various components of a url from remap.config.

    >>> parse_remap_url('http://some.host.com')
    ('http', 'some.host.com', '', '')
    >>> parse_remap_url('http://some.host.com:8080')
    ('http', 'some.host.com', '8080', '')
    >>> parse_remap_url('http://some.host.com/')
    ('http', 'some.host.com', '', '/')
    >>> parse_remap_url('https://some.host.com/a/path.xml')
    ('https', 'some.host.com', '', '/a/path.xml')
    >>> parse_remap_url('https://some.host.com:8080/a/path.xml')
    ('https', 'some.host.com', '8080', '/a/path.xml')
    """
    parsed = urlparse(url)
    if parsed.port:
        port = str(parsed.port)
    else:
        port = ''
    return parsed.scheme, parsed.hostname, port, ''.join(parsed[2:])


def remap_to_url(remap_line, no_ip):
    """
    Given a remap.config line, return the URL it references.

    >>> remap_to_url(r"map http://some.url.example.com/hostname       http://127.0.0.1:8002/hostname", no_ip=False)
    'http://some.url.example.com/hostname'

    >>> remap_to_url(r"map http://some.url.example.com/hostname       http://127.0.0.1:8002/hostname", no_ip=True)

    >>> remap_to_url(r"map http://some.url.example.com:80/hostname    http://127.0.0.1:8002/hostname", no_ip=False)
    'http://some.url.example.com:80/hostname'

    >>> remap_line = r"map http://some.url.example.com/hostname          "
    >>> remap_line += r"http://127.0.0.1:8002/hostname @plugin=aplugin.so "
    >>> remap_line += r"@pparam=/home/ts//no_negative_cache-ycs.config @plugin=bplugin.so "
    >>> remap_line += r"@pparam=--option1=candy @pparam=--option2=cane"
    >>> remap_to_url(remap_line, no_ip=False)
    'http://some.url.example.com/hostname'
    >>>
    """
    remap_line = remap_line.strip()
    if not remap_line.startswith('map'):
        return
    urls = remap_line.split()
    if len(urls) < 3:
        # If this is a remap line, there should be at least the directive
        # ("map", "regex_map", etc.), and the source and dest URLs.
        return

    src_url = urls[1]
    try:
        scheme, hostname, port, suffix = parse_remap_url(src_url)
    except ValueError:
        return
    if re.match('[a-zA-Z0-9]', hostname) is None:
        return

    if no_ip:
        try:
            dest_url = urls[2]
            _, dest_hostname, _, _ = parse_remap_url(dest_url)
            ipaddress.ip_address(dest_hostname)
            # If we get here, the hostname was an IP address and the user
            # doesn't want that.
            return
        except ValueError:
            # The hostname was a valid IP address.
            pass

    if port:
        return "{}://{}:{}{}".format(scheme, hostname, port, suffix)
    else:
        return "{}://{}{}".format(scheme, hostname, suffix)


def parse_args():
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('remap_config', metavar='remap-config', type=argparse.FileType('r'),
                        help='Path to the remap.config file from which to parse URLs.')
    parser.add_argument('-o', '--output', type=argparse.FileType('w'), default=sys.stdout,
                        help='A filename to which to write the list of URLs. Defaults to stdout.')
    parser.add_argument('--no-ip', dest='no_ip', action='store_true', required=False,
                        help='Ignore ip address (in the "replacement" section) in the remap.config file.')
    return parser.parse_args()


def main():
    args = parse_args()

    # Keep track of the set of already seen URLs so we can detect duplicates.
    urls = set()
    for line in args.remap_config:
        url = remap_to_url(line, args.no_ip)
        if url is None:
            continue
        if url in urls:
            continue
        urls.add(url)
        args.output.write(url + '\n')
    return 0


if __name__ == '__main__':
    import doctest
    doctest.testmod()
    sys.exit(main())
