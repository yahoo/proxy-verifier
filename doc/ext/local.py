# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#

from docutils import nodes
from docutils.parsers import rst
from sphinx.domains import Domain
import os.path


# This is a place to hang git file references.
class HTTPReplayDomain(Domain):
    """
    HTTP Replay.
    """

    name = 'httpreplay'
    label = 'HTTPReplay'
    data_version = 1


def make_github_link(name, rawtext, text, lineno, inliner, options={}, content=[]):
    """
    This docutils role lets us link to source code via the handy :swoc:git: markup.
    """
    url = 'https://github.com/yahoo/proxy-verifier/blob/{}/{}'
    ref = 'master'
    node = nodes.reference(rawtext, os.path.basename(text), refuri=url.format(ref, text), **options)
    return [node], []


def setup(app):
    rst.roles.register_generic_role('arg', nodes.emphasis)
    rst.roles.register_generic_role('const', nodes.literal)
    rst.roles.register_generic_role('pack', nodes.strong)

    app.add_domain(HTTPReplayDomain)

    # this lets us do :httpreplay:git:`<file_path>` and link to the file on github
    app.add_role_to_domain('httpreplay', 'git', make_github_link)
