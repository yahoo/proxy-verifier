#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


def main():
    base_url = "http://example.one?"
    param = "parm{0:04d}={1:06X}"
    param_len = 16
    total = int((1600 - 32) / param_len)
    for i in range(1, total):
        size = len(base_url)
        print(base_url, end="")
        test_semi = i - 1
        for j in range(1, i):
            size += param_len
            print(param.format(j, size), end="")
            if j != test_semi:
                print(";", end="")
        print("")


if __name__ == "__main__":
    main()
