#!/usr/bin/env python3
'''
Filter HTTP/3 test output to stable verification lines.
'''
# @file
#
# Copyright 2026, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import re
import sys

TRANSACTION_RE = re.compile(r'Parsed (?P<count>\d+) transactions in (?P<sessions>\d+) sessions')
FIELD_SUCCESS_RE = re.compile(r'(?P<kind>Equals|Absence) Success: Key: "(?P<key>[^"]+)", '
                              r'Field Name: "(?P<field>[^"]+)"(?:, Value: "(?P<value>[^"]+)")?')
CONTENT_SUCCESS_RE = re.compile(
    r'(?P<kind>Prefix|Suffix) Success: Key: "(?P<key>[^"]+)", Content Data: "(?P<field>[^"]+)", '
    r'Required Value: "(?P<value>[^"]*)"')


def escape_value(value):
    """Return @a value with whitespace made visible for gold files."""
    return value.replace("\\", "\\\\").replace(" ", "\\s")


def summarize_line(line):
    """Return a stable summary for an HTTP/3 verifier output line."""
    if match := TRANSACTION_RE.search(line):
        return f"parsed transactions={match.group('count')} sessions={match.group('sessions')}"

    if match := FIELD_SUCCESS_RE.search(line):
        summary = f"{match.group('kind').lower()} key={match.group('key')} field={match.group('field')}"
        if match.group('value') is not None:
            summary += f" value={match.group('value')}"
        return summary

    if match := CONTENT_SUCCESS_RE.search(line):
        return (
            f"{match.group('kind').lower()} key={match.group('key')} field={match.group('field')} "
            f"value={escape_value(match.group('value'))}")

    return None


def summarize_file(label, path):
    """Yield filtered output from @a path, prefixed with @a label."""
    parsed = []
    successes = []
    with open(path, encoding='utf-8') as input_file:
        for line in input_file:
            if summary := summarize_line(line):
                if summary.startswith("parsed "):
                    parsed.append(summary)
                else:
                    successes.append(summary)

    for summary in parsed:
        yield f"{label}: {summary}"
    for summary in sorted(successes):
        yield f"{label}: {summary}"


def parse_proxy_header(line):
    """Parse a proxy output header line into a name/value pair."""
    if line.startswith(":"):
        name, value = line[1:].split(":", 1)
        return f":{name}", value.strip()

    name, value = line.split(":", 1)
    return name, value.strip()


def read_header_block(lines, index):
    """Read proxy header lines from @a lines starting at @a index."""
    headers = []
    while index < len(lines):
        line = lines[index].rstrip("\n")
        index += 1
        if line == "":
            break
        headers.append(parse_proxy_header(line))
    return headers, index


def summarize_proxy_output(path):
    """Yield stable request and response header summaries from proxy output."""
    with open(path, encoding='utf-8') as input_file:
        lines = input_file.readlines()

    transactions = []
    index = 0
    while index < len(lines):
        line = lines[index].rstrip("\n")
        index += 1
        if line != "==== REQUEST HEADERS ====":
            continue

        request_headers, index = read_header_block(lines, index)
        response_status = None
        response_headers = []
        while index < len(lines):
            line = lines[index].rstrip("\n")
            index += 1
            if line == "==== RESPONSE ====":
                if index < len(lines):
                    response_status = lines[index].rstrip("\n")
                    index += 1
            elif line == "==== RESPONSE HEADERS ====":
                response_headers, index = read_header_block(lines, index)
                break

        key = next((value for name, value in request_headers if name.lower() == "uuid"),
                   str(len(transactions) + 1))
        transactions.append((key, request_headers, response_status, response_headers))

    for key, request_headers, response_status, response_headers in sorted(transactions):
        for name, value in sorted(request_headers, key=lambda item: item[0].lower()):
            yield f"proxy: request key={key} {name}={value}"
        yield f"proxy: response key={key} status={response_status}"
        for name, value in sorted(response_headers, key=lambda item: item[0].lower()):
            yield f"proxy: response key={key} {name}={value}"


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proxy-output", help="The HTTP/3 proxy stdout file.")
    parser.add_argument("client_output", nargs="?", help="The HTTP/3 client stdout file.")
    parser.add_argument("server_output", nargs="?", help="The HTTP/3 server stdout file.")
    return parser.parse_args()


def main():
    """Print stable HTTP/3 verifier output."""
    args = parse_args()
    if args.client_output is not None or args.server_output is not None:
        if args.client_output is None or args.server_output is None:
            print("client and server output paths must be provided together", file=sys.stderr)
            return 1
        for line in summarize_file("client", args.client_output):
            print(line)
        for line in summarize_file("server", args.server_output):
            print(line)

    if args.proxy_output is not None:
        for line in summarize_proxy_output(args.proxy_output):
            print(line)

    return 0


if __name__ == "__main__":
    sys.exit(main())
