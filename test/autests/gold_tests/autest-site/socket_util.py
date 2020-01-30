'''
Implement socket manipulation helper functions.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


def create_address_argument(ports, use_ipv6=False):
    """
    >>> create_address_argument([8080, 8081])
    '"127.0.0.1:8080,127.0.0.1:8081"'
    >>> create_address_argument([8080, 8081])
    '"[::1]:8080,[::1]:8081"'
    """
    is_first = True
    argument = '"'
    address = '127.0.0.1'
    if use_ipv6:
        address = '[::1]'
    for port in ports:
        if is_first:
            is_first = False
        else:
            argument += ','
        # We'll have a trailing ',', but verifier-server handles that fine.
        argument += "{}:{}".format(address, port)
    argument += '"'
    return argument
