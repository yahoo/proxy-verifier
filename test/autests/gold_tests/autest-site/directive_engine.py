'''
Implement X-Proxy-Directive behavior.
'''
# @file
#
# Copyright 2020, Verizon Media
# SPDX-License-Identifier: Apache-2.0
#


import re


class Directive:
    """
    The base class for the logic of a single directive.
    """
    def apply(self, headers):
        """
        The public interface of all Directive objects.

        Derived classes must implement the _apply function which implements its
        particular logic against headers.

        Args:
            headers: The headers upon which the directive acts.

        Returns:
            The new headers after the directive manipulates them.
        """
        return self._apply(headers)

    @staticmethod
    def directive_factory(command, value):
        """
        Generate a Directive from a directive description.

        >>> d = Directive.directive_factory("delete", "X-Test-Header")
        >>> type(d) == DeleteDirective
        True
        >>> d = Directive.directive_factory("insert", "X-Request-ID: 3")
        >>> type(d) == InsertDirective
        True
        """
        if command.lower() == DeleteDirective._command_name.lower():
            return DeleteDirective(value)
        if command.lower() == InsertDirective._command_name.lower():
            return InsertDirective(value)


class DeleteDirective(Directive):
    """
    Implement the deletion directive.

    This is associated with the Delete=%<field_name%> specification. All fields
    with the name field_name, matched case insensitively, will be deleted.
    """

    _command_name = "Delete"

    def __init__(self, field_name_to_delete):
        self._field_name_to_delete = field_name_to_delete

    def _apply(self, headers):
        """
        >>> import email.message
        >>> headers = email.message.Message()
        >>> headers.add_header('X-tEsT', 'Candy-CANE')
        >>> headers.add_header('Host', 'example.com')
        >>> d = DeleteDirective('x-test')
        >>> new_headers = d.apply(headers)
        >>> len(new_headers)
        1
        >>> new_headers['host']
        'example.com'

        Nothing happens if the requested field is not in the headers.

        >>> d = DeleteDirective('x-non-existent')
        >>> new_headers = d.apply(new_headers)
        >>> len(new_headers)
        1
        >>> new_headers['host']
        'example.com'
        """
        del headers[self._field_name_to_delete]
        return headers


class InsertDirective(Directive):
    """
    Implement the insertion directive.

    This is associated with the Insert=%<field_name: field_value%>
    specification.  After apply is called, the headers will have the new
    "field_name: field_value" added to them. White space between field_name and
    field_value is optional.
    """

    _command_name = "Insert"

    def __init__(self, field_to_insert):
        colon_index = field_to_insert.find(':')
        if colon_index == -1:
            raise ValueError("Insert directive value has no colon: "
                             "{}".format(field_to_insert))
        self._new_field_name = field_to_insert[:colon_index].strip()
        self._new_field_value = field_to_insert[colon_index+1:].strip()

    def _apply(self, headers):
        """
        >>> import email.message
        >>> headers = email.message.Message()
        >>> headers.add_header('Host', 'data.flurry.com')
        >>> d = InsertDirective('x-request-id:3')
        >>> new_headers = d.apply(headers)
        >>> len(new_headers)
        2
        >>> new_headers['host']
        'data.flurry.com'
        >>> new_headers['X-Request-ID']
        '3'

        Inserting an already existing field replaces it.
        >>> d = InsertDirective('x-request-id:    5')
        >>> new_headers = d.apply(new_headers)
        >>> len(new_headers)
        2
        >>> new_headers['host']
        'data.flurry.com'
        >>> new_headers['X-Request-ID']
        '5'
        """
        # We delete to ensure there we don't add a duplicate header.
        del headers[self._new_field_name]
        headers[self._new_field_name] = self._new_field_value
        return headers


class DirectiveEngine:
    """
    Implements directive parsing and header manipulation.

    X-Proxy-Directive: Delete=%<field_name_to_delete%>
      This header requests that the proxy not forward on header fields with
      <field_name_to_delete> as their name.

    X-Proxy-Directive: Insert=%<field_name: field_value%>
      This header requests the proxy to insert a header with name <field_name>
      and value <field_value>. If a header with <field_name> already exists,
      then its value is modified to match the provided <field_value>.

    Multiple directives can be passed in the same X-Proxy-Directive by simply
    appending them in the value of the header. White space may be used as a
    separator. For instance:

        X-Proxy-Directive: Delete=%<X-Test%> Insert=%<X-Request-ID: 23%>

    This header will both delete the X-Test header, if it exists, and insert
    or modify an existing X-Request-ID header to have the value 23.

    In addition to the above manipulations, the X-Proxy-Directive is filtered
    out via get_new_headers.
    """

    PROXY_DIRECTIVE_FIELD_NAME = 'X-Proxy-Directive'

    def __init__(self, headers):
        self._original_headers = headers
        self._x_proxy_directive_value = None
        self._split_directive_values = []
        self._directives = []

        if DirectiveEngine.PROXY_DIRECTIVE_FIELD_NAME in headers:
            self._x_proxy_directive_value = \
                    headers[DirectiveEngine.PROXY_DIRECTIVE_FIELD_NAME]
            self._split_directive_values = DirectiveEngine._directive_value_parser(
                    self._x_proxy_directive_value)

            for command, value in self._split_directive_values:
                self._directives.append(Directive.directive_factory(command, value))

    @staticmethod
    def _directive_value_parser(x_proxy_directive_value):
        """
        >>> DirectiveEngine._directive_value_parser('')
        []
        >>> DirectiveEngine._directive_value_parser("Delete=%<X-TestHeader%>")
        [('Delete', 'X-TestHeader')]
        >>> DirectiveEngine._directive_value_parser("Insert=%<X-TestHeader: from_proxy_response%>")
        [('Insert', 'X-TestHeader: from_proxy_response')]
        >>> DirectiveEngine._directive_value_parser("Delete=%<X-Test%>Insert=%<X-WOW:    3%>")
        [('Delete', 'X-Test'), ('Insert', 'X-WOW:    3')]
        """
        return re.findall("(Delete|Insert)=%<(.*?)%>", x_proxy_directive_value)

    def get_new_headers(self):
        """
        Apply each of the X-Proxy-Directive specified directives and, if it
        exists, also remove the X-Proxy-Directive field itself.

        Return:
            The new header values after the above-described manipulations are applied to them.

        >>> import email.message
        >>> headers = email.message.Message()
        >>> headers.add_header('Host', 'example.com')
        >>> headers.add_header('X-Test-Header', 'something')
        >>> headers.add_header('X-Duplicate-Header', 'one')
        >>> headers.add_header('X-Duplicate-Header', 'two')
        >>> headers.add_header('X-Proxy-Directive', 'Delete=%<x-test-header%> Insert=%<X-Request-ID: 4%>')
        >>> e = DirectiveEngine(headers)
        >>> new_headers = e.get_new_headers()
        >>> len(new_headers)
        4
        >>> new_headers['host']
        'example.com'
        >>> new_headers['X-Request-ID']
        '4'
        >>> new_headers['X-Duplicate-Header']
        'one'
        >>> new_headers.items()
        [('Host', 'example.com'), ('X-Duplicate-Header', 'one'), ('X-Duplicate-Header', 'two'), ('X-Request-ID', '4')]
        """
        new_headers = self._original_headers
        for directive in self._directives:
            new_headers = directive.apply(new_headers)
        del new_headers[DirectiveEngine.PROXY_DIRECTIVE_FIELD_NAME]
        return new_headers


if __name__ == '__main__':
    import doctest
    doctest.testmod()
