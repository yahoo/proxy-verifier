#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#
import copy
import json
import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 <path/replay_generator.py> <length of longest URL desired (multiple of 16, plus 2)>")
        print("    (For example, 18 gives one URL of length 18, and 34 gives two URLs, of lengths 18 and 34)")
        sys.exit()

    base_url = "http://example.one"
    param = "parm{0:04d}={1:06X}"
    param_len = 16
    param_offset = 14
    total = int((int(sys.argv[1]) + param_offset) / param_len)  # 8160

    globals_node = {"encoding": "esc_json", "fields": []}
    meta_node = {"version": "1.0", "global_field_rules": globals_node}
    transactions_array = []
    uuid = 0

    for i in range(1, total):
        uuid += 1
        size = len(base_url)
        out_url = base_url
        test_semi = i - 1
        for j in range(1, i):
            size += param_len
            out_url += param.format(j, size)
            if j != test_semi:
                out_url += ";"
        if i == 1:
            base_url += "?"
        uuid_str = str(uuid)

        req_fields_node = [["Host", "example.one"], ["uuid", uuid_str]]
        rsp_fields_node = copy.copy(req_fields_node)
        rsp_fields_node.append(["Content-Length", "6128"])
        req_headers_node = {"encoding": "esc_json", "fields": req_fields_node}
        rsp_headers_node = {"encoding": "esc_json", "fields": rsp_fields_node}

        req_rules_node = {}
        rsp_rules_node = {}

        client_req_node = {"version": "1.1",
                           "scheme": "https", "method": "GET", "url": out_url}
        server_rsp_node = {"status": 200,
                           "reason": "OK", "content": {"size": 6128}}

        proxy_rsp_node = copy.copy(server_rsp_node)
        proxy_req_node = copy.copy(client_req_node)

        client_req_node["headers"] = req_headers_node
        server_rsp_node["headers"] = rsp_headers_node
        proxy_req_node["headers"] = req_rules_node
        proxy_rsp_node["headers"] = rsp_rules_node

        transactions_node = {"uuid": uuid_str, "client-request": client_req_node,
                             "proxy-request": proxy_req_node, "server-response": server_rsp_node, "proxy-response": proxy_rsp_node}
        transactions_array.append(transactions_node)

    session_node = [{"protocols": ["h2", "tcp", "ipv6"],
                     "transactions": transactions_array}]
    root_node = {"meta": meta_node, "sessions": session_node}
    print(json.dumps(root_node, indent=4))


if __name__ == "__main__":
    main()
