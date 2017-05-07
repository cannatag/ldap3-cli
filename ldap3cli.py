import socket
from operator import itemgetter

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES, SIMPLE, NONE, DSA, SCHEMA, ALL, STRING_TYPES, ANONYMOUS, SASL, NTLM, BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPInvalidFilterError
from ldap3.protocol.oid import decode_syntax

desc_bg = 'black'
desc_fg = 'green'
desc_bold = True
value_bg = 'black'
value_fg = 'white'
value_bold = False
error_fg = 'red'
error_bg = 'black'
error_bold = True
title_fg = 'yellow'
title_bg = 'black'
title_bold = True

sorting = {'category': 0,
           'name': 1,
           'oid': 2,
           'type': 3}

INDENT = 2


def apply_style(style, string):
    if style == 'title':
        return click.style(string, fg = title_fg, bg=title_bg, bold=title_bold)
    elif style == 'desc':
        return click.style(string, fg = desc_fg, bg=desc_bg, bold=desc_bold)
    elif style == 'value':
        return click.style(string, fg = value_fg, bg=value_bg, bold=value_bold)
    elif style == 'error':
        return click.style(string, fg = error_fg, bg=error_bg, bold=error_bold)
    else:
        return string


def display_entry(counter, entry):
    echo_detail(str(counter).rjust(4), click.style(entry.entry_dn, fg=title_fg, bg=title_bg, bold=title_bold))
    for attribute in sorted(entry.entry_attributes):
        echo_detail(attribute, entry[attribute], level=5)


def display_response(counter, response):
    echo_detail(str(counter).rjust(4), click.style(response['dn'], fg=title_fg, bg=title_bg, bold=title_bold))
    for attribute in sorted(response['attributes']):
        echo_detail(' ' * 7 + attribute, response['attributes'][attribute], level=0)


def syntax_description(syntax):
    if not syntax:
        return ''

    decoded = decode_syntax(syntax)
    if decoded and decoded[2] != 'Uknwown':
        return decoded[2]
    else:
        return syntax


def list_to_string(list_object):
    if not list_object:
        return ''

    if not isinstance(list_object, SEQUENCE_TYPES):
        return list_object

    r = ''
    for element in list_object:
        r += (list_to_string(element) if isinstance(element, SEQUENCE_TYPES) else str(element)) + ', '

    return r[:-2] if r else ''


def ljust_style(string, col, styles, lengths, fill=' '):
    if not string:
        string = ''
    length = lengths[col]
    unstyled = click.unstyle(string)
    if len(unstyled) == len(string): # not already styled
        if styles:
            string = apply_style(styles[col], string)
    if len(unstyled) < length:
        return string + fill * (length - len(unstyled))

    return string


def build_table(name, heading, rows, styles=None, sort=None, max_width=50, level=0):
    if rows:
        if max_width == 0:
            max_width = 99999
        lengths = dict()
        max_cols = max(len(heading), len(rows[0]))
        for col in range(max_cols):
            lengths[col] = 0
            for row in [heading] + rows:
                if row:
                    # print(col, row)
                    if isinstance(row[col], SEQUENCE_TYPES):
                        for el in row[col]:
                            lengths[col] = max(len(click.unstyle(str(el))[:max_width]), lengths[col])
                    else:
                        lengths[col] = max(len(click.unstyle(str(row[col]))[:max_width]), lengths[col])
        if heading:
            table = [' | '.join([ljust_style(str(element)[:max_width], col, styles, lengths) for col, element in enumerate(heading)]),
                     ' | '.join([''.ljust(min(lengths[col], max_width), '=') for col, element in enumerate(heading)])]
        else:
            table = []
        if sort and not isinstance(sort, SEQUENCE_TYPES):
            sort = [sort]
        for row in sorted(rows, key=lambda x: [x[i].lower() if hasattr(x[i], 'lower') else x[i] for i in sort]) if sort is not None else rows:
            table_row = []
            print(row)
            for col, element in enumerate(row):
                if col == 2:
                    print(col, element)
                if isinstance(element, SEQUENCE_TYPES):
                    if element:
                        for pos, el in enumerate(sorted(element)):
                            print(col, element, pos, el)

                            if pos == 0:
                                table_row.append(ljust_style(str(el)[:max_width], col, styles, lengths))
                            else:
                                for remaining in range(col, max_cols - 1):
                                    table_row.append('')
                                table.append(' | '.join(table_row))
                                table_row = []
                                for starting in range(0, col):
                                    table_row.append(ljust_style('', starting, styles, lengths))
                                table_row.append(ljust_style(str(el)[:max_width], col, styles, lengths))
                    else:
                        table_row.append(ljust_style('', col, styles, lengths))
                else:
                    print(col, element)

                    table_row.append(ljust_style(str(element)[:max_width], col, styles, lengths))

            table.append(' | '.join(table_row))
    else:
        table = ['']
    if name:
        echo_title(name, level=level)
    echo_detail_multiline('', table, level=level + (1 if name else 0))


def echo_empty_line(number=1):
    for num in range(number):
        click.echo('', nl=True)

def echo_title(string, level=0):
    click.secho(' ' * INDENT * level + string, fg=title_fg, bg=title_bg, bold=title_bold)


def echo_detail(desc, value, error=False, level=1):
    click.secho(' ' * INDENT * level + desc + (': ' if desc.strip() else ''), fg=desc_fg, bg=desc_bg, bold=desc_bold, nl=False)
    if error:
        click.secho(str(value), fg=error_fg, bg=error_bg, bold=error_bold)
    else:
        click.secho(str(value), fg=value_fg, bg=value_bg, bold=value_bold)


def echo_detail_multiline(desc, value, error=False, level=1):
    if isinstance(value, SEQUENCE_TYPES):
        lines = value
    else:
        lines = value.split('\r\n' if '\r\n' in value else '\n')

    first = False
    for line in lines:
        if not first:
            echo_detail(desc, line, level=level)
            first = True
        else:
            echo_detail(' ' * len(desc), line, level=level)


class Session(object):
    def __init__(self, host, port, use_ssl, user, password, authentication, get_info, usage, debug):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.user = user
        self.password = password
        self.server = None
        self.connection = None
        if authentication == 'anonymous':
            self.authentication = ANONYMOUS
        elif authentication == 'simple':
            self.authentication = SIMPLE
        elif authentication == 'sasl':
            self.authentication = SASL
        else:
            self.authentication = NTLM
        if get_info == 'none':
            self.info = NONE
        elif get_info == 'dsa':
            self.info = DSA
        elif get_info == 'schema':
            self.info = SCHEMA
        else:
            self.info = ALL
        self.usage = usage
        self.debug = debug
        self.server = Server(self.host, self.port, self.use_ssl, get_info=self.info)
        self.connection = Connection(self.server, self.user, self.password, authentication=authentication, raise_exceptions=False, collect_usage=self.usage)
        self.login_result = None

    @property
    def valid(self):
        return True if self.connection.bound else False

    def done(self):
        self.connection.unbind()
        if self.usage:
            echo_empty_line()
            table = []
            table.append(['Time', 'Total', self.connection.usage.elapsed_time])
            table.append(['', 'Socket open at', str(self.connection.usage.open_socket_start_time.isoformat()) if self.connection.usage.open_socket_start_time else ''])
            table.append(['', 'Socket closed at', str(self.connection.usage.connection_stop_time.isoformat()) if self.connection.usage.connection_stop_time else ''])
            table.append(['Server', 'From pool', self.connection.usage.servers_from_pool])
            table.append(['', 'Sockets open', self.connection.usage.open_sockets])
            table.append(['', 'Sockets closed', self.connection.usage.closed_sockets])
            table.append(['', 'TLS sockets', self.connection.usage.wrapped_sockets])
            table.append(['Bytes', 'Total', self.connection.usage.bytes_transmitted + self.connection.usage.bytes_received])
            table.append(['', 'Transmitted', self.connection.usage.bytes_transmitted])
            table.append(['', 'Received', self.connection.usage.bytes_received])
            table.append(['Messages', 'Total', self.connection.usage.messages_transmitted + self.connection.usage.messages_received])
            table.append(['', 'Transmitted', self.connection.usage.messages_transmitted])
            table.append(['', 'Received', self.connection.usage.messages_received])
            table.append(['Operations', 'Total', self.connection.usage.operations])
            table.append(['', 'Abandon', self.connection.usage.abandon_operations])
            table.append(['', 'Bind', self.connection.usage.bind_operations])
            table.append(['', 'Add', self.connection.usage.add_operations])
            table.append(['', 'Compare', self.connection.usage.compare_operations])
            table.append(['', 'Delete', self.connection.usage.delete_operations])
            table.append(['', 'Extended', self.connection.usage.extended_operations])
            table.append(['', 'Modify', self.connection.usage.modify_operations])
            table.append(['', 'Modify DN', self.connection.usage.modify_dn_operations])
            table.append(['', 'Search', self.connection.usage.search_operations])
            table.append(['', 'Unbind', self.connection.usage.unbind_operations])
            table.append(['Referrals', 'Received', self.connection.usage.referrals_received])
            table.append(['', 'Followed', self.connection.usage.referrals_followed])
            table.append(['', 'Connections', self.connection.usage.referrals_connections])
            build_table('Session metrics',
                        [],
                        table,
                        styles=['title', 'desc', 'value'],
                        level=0)

    def connect(self):
        if self.connection and not self.connection.bound:
            try:
                self.connection.bind()
            except LDAPSocketOpenError as e:
                if self.debug:
                    if isinstance(e.args[1], SEQUENCE_TYPES):
                        for arg in e.args[1]:
                            click.secho(str(arg[0]) + ' ', fg='yellow', nl=False)
                            click.secho(str(arg[2]) + ' ', fg='red', bold=True, nl=False)
                            click.secho(str(arg[3]) + ' ', fg='red')
                    else:
                        click.secho(str(e.args), color='red', bold=True)
                raise click.ClickException('unable to connect to %s on port %s - reason: %s' % (self.host, self.port, e.args[0] if isinstance(e.args, SEQUENCE_TYPES) else e))
            self.login_result = self.connection.last_error

@click.group()
@click.option('-a', '--authentication', type=click.Choice(['anonymous', 'simple', 'sasl', 'ntlm']), help='type of authentication')
@click.option('-h', '--host', default='localhost', help='LDAP server hostname or ip address')
@click.option('-p', '--port', type=click.IntRange(0, 65535), help='LDAP server port')
@click.option('-u', '--user', help='dn or user name')
@click.option('-w', '--password', help='password')
@click.option('-W', '--request-password', is_flag=True, help='hidden prompt for password at runtime')
@click.option('-s', '--ssl', is_flag=True, help='establish a SSL/TLS connection')
@click.option('-i', '--server_info', type=click.Choice(['none', 'dsa', 'schema', 'all']), default='all', help='info requested to server')
@click.option('-m', '--metrics', is_flag=True, help='display usage metrics')
@click.option('-d', '--debug', is_flag=True, help='enable debug output')
@click.pass_context
def cli(ctx, host, port, user, password, ssl, request_password, authentication, server_info, metrics, debug):
    """LDAP for humans"""
    if request_password and not password:
        password = click.prompt('Password <will not be shown>', hide_input=True, type=click.STRING)
    if ssl and not port:
        port = 636
    elif not port:
        port = 389
    ctx.obj = Session(host, port, ssl, user, password, authentication, server_info, metrics, debug)


@cli.command()
@click.pass_obj
@click.option('-j', '--json', is_flag=True, help='format output as JSON')
@click.option('-m', '--max-width', type=int, default=50, help='max column width')
@click.option('-s', '--sort', type=click.Choice(['name', 'oid', 'type']), default='name', help='sorting column')
@click.argument('type', type=click.Choice(['connection', 'server', 'schema', 'all']), default='connection')
def info(session, type, json, sort, max_width):
    """Bind and get info"""
    session.connect()
    if type in ['connection', 'all']:
        if session.valid:
            build_table('',
                        [],
                        [['Connection ', 'Status', 'valid'],
                         ['', 'Host', session.connection.server.host],
                         ['', 'Port', session.connection.server.port],
                         ['', 'Encryption' if session.use_ssl else apply_style('error', 'Encryption'), 'SSL' if session.use_ssl else 'CLEARTEXT'],
                         ['', 'User', session.connection.user],
                         ['', 'Authentication', session.connection.authentication],
                         ['', '', ''],
                         ['Socket     ', 'Family', session.connection.socket.family],
                         ['', 'Type', session.connection.socket.type],
                         ['', 'Local', ' - '.join([str(el) for el in session.connection.socket.getsockname()])],
                         ['', 'Remote', ' - '.join([str(el) for el in session.connection.socket.getpeername()])],
                         ['', '', ''],
                         ['TLS        ', 'Status' if session.connection.server.ssl else apply_style('error', 'Status'), 'established' if session.connection.server.ssl else 'NOT established'],
                         ['', 'Version', session.connection.socket.version() if session.connection.server.ssl else '-'],
                         ['', 'Cipher', ' - '.join([str(el) for el in session.connection.socket.cipher()]) if session.connection.server.ssl else '-'],
                         ['Server info', 'Status' if session.connection.server.info else apply_style('error', 'Status'), 'No info returned by server' if not session.connection.server.info else 'Present - use "info server" to show'],
                         ['Schema info', 'Status' if session.connection.server.schema else apply_style('error', 'Status'), 'No schema returned by server' if not session.connection.server.schema else 'Present - use "info schema" to show']
                         ],
                        styles=['title', 'desc', 'value'],
                        max_width=max_width)
        else:
            echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)
    if type in ['server', 'all']:
        if session.valid:
            if json:
                echo_detail_multiline('', session.connection.server.info.to_json())
            else:
                if not session.connection.server.info:
                    echo_detail('Status', 'NO INFO returned by server', error=True)
                else:
                    table = []
                    if session.connection.server.info.supported_ldap_versions:
                        table.append(['Standard', 'LDAP versions', session.connection.server.info.supported_ldap_versions])
                    if session.connection.server.info.supported_sasl_mechanisms:
                        table.append(['', 'SASL mechanisms', session.connection.server.info.supported_sasl_mechanisms])
                    if session.connection.server.info.vendor_name:
                        table.append(['', 'Vendor name', session.connection.server.info.vendor_name])
                    if session.connection.server.info.vendor_version:
                        table.append(['', 'Vendor version', session.connection.server.info.vendor_version])
                    if session.connection.server.info.alt_servers:
                        table.append(['', 'Alternate servers', session.connection.server.info.alt_servers])
                    if session.connection.server.info.naming_contexts:
                        table.append(['', 'Naming contexts', session.connection.server.info.naming_contexts])
                    if session.connection.server.info.schema_entry:
                        table.append(['', 'Schema entry', session.connection.server.info.schema_entry])

                    build_table('Server (DSA) info',
                                [],
                                table,
                                styles=['title', 'desc', 'value'],
                                max_width=max_width,
                                level=0)

                    if session.connection.server.info.other:
                        echo_empty_line()
                        table = []
                        for i, (key, value) in enumerate(sorted(session.connection.server.info.other.items())):
                            table.append(['Custom  ' if i == 0 else '', key, value])
                        build_table('',
                                    [],
                                    table,
                                    styles=['title', 'desc', 'value'],
                                    max_width=max_width,
                                    level=1)

                    table = []
                    if session.connection.server.info.supported_controls:
                        for pos, element in enumerate(session.connection.server.info.supported_controls):
                            table.append(['Control', element[2] if element[2] else '', element[0] if element[0] else '', element[3] if element[3] else ''])
                    if session.connection.server.info.supported_extensions:
                        for pos, element in enumerate(session.connection.server.info.supported_extensions):
                            table.append(['Extension', element[2] if element[2] else '', element[0] if element[0] else '', element[3] if element[3] else ''])
                    if session.connection.server.info.supported_features:
                        for pos, element in enumerate(session.connection.server.info.supported_features):
                            table.append(['Feature', element[2] if element[2] else '', element[0] if element[0] else '', element[3] if element[3] else ''])
                    if table:
                        echo_empty_line()
                        build_table('Capabilities',
                                    ['category', 'name', 'OID', 'description'],
                                    table,
                                    sort=(sorting['category'], sorting[sort]),
                                    styles=['title', 'desc', 'value', 'value'],
                                    max_width=max_width,
                                    level=0)

        elif type != 'all':
            echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)

    if type in ['schema', 'all']:
        if session.valid:
            if json:
                echo_detail_multiline('', session.connection.server.schema.to_json())
            else:
                if not session.connection.server.schema:
                    echo_detail('Status', 'NO SCHEMA returned by server', error=True)
                else:
                    echo_title('Schema info')
                    if session.connection.server.schema.object_classes:
                        build_table('Object classes',
                                    ['name', 'OID', 'type (kind)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      element[1].kind,
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.object_classes.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('Object classes', 'not present')

                    if session.connection.server.schema.attribute_types:
                        echo_empty_line()
                        build_table('Attribute types',
                                    ['name', 'OID', 'type (syntax)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      syntax_description(element[1].syntax),
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.attribute_types.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)

                    else:
                        echo_detail('Attribute types', 'not present')

                    if session.connection.server.schema.matching_rules:
                        echo_empty_line()
                        build_table('Matching rules',
                                    ['name', 'OID', 'type (syntax)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      list_to_string(element[1].syntax),
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                    for element in session.connection.server.schema.matching_rules.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('Matching rules', 'not present')

                    if session.connection.server.schema.matching_rule_uses:
                        echo_empty_line()
                        build_table('Matching rule uses',
                                    ['name', 'OID', 'type (apply to)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      list_to_string(element[1].apply_to),
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.matching_rule_uses.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('Matching rule uses', 'not present')

                    if session.connection.server.schema.dit_content_rules:
                        echo_empty_line()
                        build_table('DIT content rules',
                                    ['name', 'OID', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.dit_content_rules.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('DIT content rules', 'not present')

                    if session.connection.server.schema.dit_structure_rules:
                        echo_empty_line()
                        build_table('DIT structure rules',
                                    ['name', 'OID', 'type (name form)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      list_to_string(element[1].name_form),
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.dit_structure_rules.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('DIT structure rules', 'not present')

                    if session.connection.server.schema.name_forms:
                        echo_empty_line()
                        build_table('Name forms',
                                    ['name', 'OID', 'type (object class)', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      list_to_string(element[1].object_class),
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.name_forms.items()],
                                    styles=['desc', 'value', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('Name forms', 'not present')

                    if session.connection.server.schema.ldap_syntaxes:
                        echo_empty_line()
                        temp_table = [[element[1].oid_info[2] if element[1].oid_info else element[1].oid,
                                      element[1].oid,
                                      click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.ldap_syntaxes.items()]

                        for row in temp_table:
                            if '[OBSOLETE]' in row[0] and not row[2]:
                                row[2] = click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold)
                                row[0] = row[0].replace('[OBSOLETE]', '')
                            if '[DEPRECATED]' in row[0] and not row[2]:
                                row[2] = click.style('DEPRECATED', fg=error_fg, bg=error_bg, bold=error_bold)
                                row[0] = row[0].replace('[DEPRECATED]', '')
                        build_table('LDAP syntaxes',
                                    ['name', 'OID', 'obsolete', 'description'],
                                    temp_table,
                                    styles=['desc', 'value', 'error', 'title'],
                                    sort=sorting[sort],
                                    max_width=max_width)
                    else:
                        echo_detail('LDAP syntaxes', 'not present')

                    if session.connection.server.schema.other:
                        echo_empty_line()
                        table = []
                        for i, (key, value) in enumerate(sorted(session.connection.server.schema.other.items())):
                            table.append(['Other' if i == 0 else '', key, value])
                        build_table('',
                                    [],
                                    table,
                                    styles=['title', 'desc', 'value'],
                                    max_width=max_width,
                                    level=0)
        elif type != 'all':
            echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)

    session.done()


@cli.command()
@click.pass_obj
@click.option('-s', '--scope', type=click.Choice(['base', 'level', 'subtree']), default='subtree', help='scope of search')
@click.option('-j', '--json', is_flag=True, help='format output as JSON')
@click.option('-l', '--ldif', is_flag=True, help='format output as LDIF')
@click.option('-i', '--listing', is_flag=True, help='format output as list')
@click.option('-p', '--paged', type=int, help='paged search')
@click.argument('base', type=click.STRING)
@click.argument('filter', required=False, default='(objectclass=*)')
@click.argument('attrs', nargs=-1, type=click.STRING)
def search(session, base, filter, attrs, scope, json, ldif, paged, listing):
    """Search and return entries"""
    session.connect()
    if session.valid:
        if scope == 'base':
            search_scope = BASE
        elif scope == 'level':
            search_scope = LEVEL
        else:
            search_scope = SUBTREE

        # check if an attribute is stored in the filter parameter. If so apply the default filter
        if filter.startswith('(') and filter.endswith(')') and '=' in filter:
            search_filter = filter
        else:
            search_filter = '(objectclass=*)'
            attrs = attrs + (filter, )
        try:
            if not paged:
                session.connection.search(base, search_filter, search_scope, attributes=attrs)
                responses = session.connection.response
            else:
                responses = session.connection.extend.standard.paged_search(base, search_filter, search_scope, attributes=attrs, paged_size=paged, generator=True)
        except LDAPInvalidFilterError:
            raise click.ClickException('invalid filter: %s' % filter)

        tot = 0
        table = []
        headers = ('item', 'DN') + attrs

        if json:
            click.echo(session.connection.response_to_json())
        elif ldif:
            click.echo(session.connection.response_to_ldif())
        else:
            for i, response in enumerate(responses, 1):
                tot = i
                if listing:
                    display_response(i, response)
                else:
                    # table.append([i, response['dn'], response['attributes']])
                    table.append([i, response['dn']] + [response['attributes'][attr] for attr in attrs])

            if not listing:
                build_table('Response',
                            headers,
                            table,
                            level=0)

        if not json and not ldif:
            echo_detail('Total entries', tot)
        session.done()
    else:
        echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)

if __name__ == '__main__':
    cli()
