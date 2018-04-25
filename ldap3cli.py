from datetime import datetime

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES, SIMPLE, NONE, DSA, SCHEMA, ALL, STRING_TYPES, ANONYMOUS, SASL, NTLM, BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPInvalidFilterError, LDAPExceptionError, LDAPOperationResult
from ldap3.protocol.oid import decode_syntax
from ldap3.utils.conv import to_unicode
from ldap3.utils.ciDict import CaseInsensitiveDict

# Styles
ST_DESCR = 'descr'
ST_VALUE = 'value'
ST_ERROR = 'error'
ST_TITLE = 'title'
ST_DEBUG = 'debug'
ST_TIMED = 'timed'

STYLES = {ST_DESCR: {'fg': 'green', 'bg': None, 'bold': True, 'dim': False, 'underline': False, 'blink': False, 'reverse': False},
          ST_VALUE: {'fg': 'white', 'bg': None, 'bold': False, 'dim': False, 'underline': False, 'blink': False, 'reverse': False},
          ST_ERROR: {'fg': 'yellow', 'bg': 'red', 'bold': True, 'dim': False, 'underline': False, 'blink': False, 'reverse': False},
          ST_TITLE: {'fg': 'yellow', 'bg': None, 'bold': True, 'dim': False, 'underline': False, 'blink': False, 'reverse': False},
          ST_DEBUG: {'fg': 'magenta', 'bg': 'cyan', 'bold': True, 'dim': False, 'underline': False, 'blink': False, 'reverse': False},
          ST_TIMED: {'fg': 'magenta', 'bg': 'green', 'bold': True, 'dim': False, 'underline': False, 'blink': False, 'reverse': False}
          }

INDENT = 2
H_SEPARATOR = ' | '
MAX_COL_WIDTH = 80


def sort_if_sequence(value):
    if isinstance(value, SEQUENCE_TYPES):
        return sorted(value, key=lambda x: x.lower() if hasattr(x, 'lower') else x)
    return value


def apply_style(style, string):
    if style in STYLES:
        return click.style(string,
                           fg=STYLES[style]['fg'],
                           bg=STYLES[style]['bg'],
                           bold=STYLES[style]['bold'],
                           dim=STYLES[style]['dim'],
                           underline=STYLES[style]['underline'],
                           blink=STYLES[style]['blink'],
                           reverse=STYLES[style]['reverse']
                           )
    return string


def display_entry(counter, entry):
    echo_detail(str(counter).rjust(4), apply_style(ST_TITLE, entry.entry_dn))
    for attribute in sort_if_sequence(entry.entry_attributes):
        echo_detail(attribute, entry[attribute], level=5)


def display_response(counter, response):
    echo_detail(str(counter).rjust(4), apply_style(ST_TITLE, response['dn']))
    for attribute in sort_if_sequence(response['attributes']):
        if isinstance(response['attributes'][attribute], SEQUENCE_TYPES):
            echo_detail(' ' * 7 + attribute, sort_if_sequence(response['attributes'][attribute]), level=0)
        else:
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


def ljust_style(string, col, columns_style, lengths, fill=' '):
    if not string:
        string = ''
    length = lengths[col]
    unstyled = click.unstyle(string)
    if len(unstyled) == len(string):  # not already styled
        if columns_style:
            if col >= len(columns_style):
                string = apply_style(columns_style[-1], string)  # apply last style for remaining fields
            else:
                string = apply_style(columns_style[col], string)
    if len(unstyled) < length:
        return string + fill * (length - len(unstyled))

    return string


def build_table(name, heading, rows, colums_style=None, sort=None, max_width=MAX_COL_WIDTH, level=0):
    if rows:
        if max_width == 0:
            max_width = 99999
        lengths = dict()
        max_cols = max(len(heading), len(rows[0]))
        for col in range(max_cols):
            lengths[col] = 0
            for row in [heading] + rows:
                if row:
                    if isinstance(row[col], SEQUENCE_TYPES):
                        for el in row[col]:
                            lengths[col] = max(len(click.unstyle(str(el))[:max_width]), lengths[col])
                    else:
                        lengths[col] = max(len(click.unstyle(str(row[col]))[:max_width]), lengths[col])
        if heading:
            table = [H_SEPARATOR.join([ljust_style(str(element)[:max_width], col, colums_style, lengths) for col, element in enumerate(heading)]),
                     H_SEPARATOR.join([''.ljust(min(lengths[col], max_width), '=') for col, element in enumerate(heading)])]
        else:
            table = []
        if sort and not isinstance(sort, SEQUENCE_TYPES):
            sort = [sort]
        subrows = []
        sorted_rows = sorted(rows, key=lambda x: [x[i].lower() if hasattr(x[i], 'lower') else x[i] for i in sort]) if sort is not None else rows
        for row in sorted_rows:
            max_depth = max([len(element) if isinstance(element, SEQUENCE_TYPES) else 1 for element in row])
            for depth in range(max_depth):
                subrow = []
                for col in range(max_cols):
                    if isinstance(row[col], SEQUENCE_TYPES):
                        subrow.append(ljust_style(str(row[col][depth])[:max_width], col, colums_style, lengths) if row[col] and len(row[col]) > depth else ljust_style('', col, colums_style, lengths))
                    elif depth == 0:
                        subrow.append(ljust_style(str(row[col])[:max_width], col, colums_style, lengths))
                    else:
                        subrow.append(ljust_style('', col, colums_style, lengths))
                table.append(H_SEPARATOR.join(subrow))
    else:
        table = ['']
    if name:
        echo_title(name, level=level)
    echo_detail_multiline('', table, level=level + (1 if name else 0))


def echo_empty_line(number=1):
    for num in range(number):
        click.echo('', nl=True)


def echo_title(string, level=0):
    click.echo(apply_style(ST_TITLE, ' ' * INDENT * level + string))


def echo_detail(desc, value, error=False, level=1):
    click.echo(apply_style(ST_DESCR, ' ' * INDENT * level + desc + (': ' if desc.strip() else '')), nl=False)
    if error:
        click.echo(apply_style(ST_ERROR, str(value)))
    else:
        click.echo(apply_style(ST_VALUE, str(value)))


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


def echo_debug(message):
    click.echo(apply_style(ST_TIMED, datetime.now().isoformat()) + ' - ' + apply_style(ST_DEBUG, message))


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
        elif authentication == 'sasl':
            self.authentication = SASL
        elif authentication == 'ntlm':
            self.authentication = NTLM
        elif authentication == 'simple':
            self.authentication = SIMPLE
        elif not authentication and user or password:
            self.authentication = SIMPLE
        else:
            self.authentication = ANONYMOUS
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
        self.connection = Connection(self.server, self.user, self.password, authentication=self.authentication, raise_exceptions=True, collect_usage=self.usage)
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
                        colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
                        level=0)

    def connect(self):
        if self.connection and not self.connection.bound:
            if self.debug:
                echo_debug('opening connection to %s on port %s' % (self.host, self.port))
            try:
                self.connection.open()
            except LDAPSocketOpenError as e:
                raise click.ClickException('unable to connect to %s on port %s - reason: %s' % (self.host, self.port, str(e.args[0]) if isinstance(e.args, SEQUENCE_TYPES) else str(e.args)))
            try:
                self.connection.bind()
            except LDAPExceptionError as e:
                raise click.ClickException('unable to bind to %s on port %s - reason: %s' % (self.host, self.port, str(e.args[0]) if isinstance(e.args, SEQUENCE_TYPES) else str(e.args)))
            except LDAPOperationResult as e:
                raise click.ClickException('server response when binding to %s on port %s - reason: %s' % (self.host, self.port, str(e).replace(' - None', '')))
            finally:
                if self.debug:
                    echo_debug('REQUEST:' + str(self.connection.request))
                if self.debug:
                    echo_debug('RESULT:' + str(self.connection.result))
            self.login_result = self.connection.result['description'] + ' - ' + self.connection.result['message']


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
@click.version_option()
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


@click.command()
@click.pass_obj
@click.option('-j', '--json', is_flag=True, help='format output as JSON')
@click.option('-m', '--max-width', type=int, default=50, help='max column width')
@click.option('-s', '--sort', type=click.Choice(['name', 'oid', 'type']), default='name', help='sorting column')
@click.argument('type', type=click.Choice(['connection', 'server', 'schema', 'all']), default='connection')
def info(session, type, json, sort, max_width):
    """Bind and get info
    TYPE can be connection, server, schema or all"""
    session.connect()
    sort_col = 0
    if sort:
        if sort == 'name':
            sort_col = 1
        elif sort == 'oid':
            sort_col = 2
        elif sort == 'type':
            sort_col = 3

    if type in ['connection', 'all']:
        if session.valid:
            build_table('',
                        [],
                        [['Connection ', 'Status', 'valid'],
                         ['', 'Host', session.connection.server.host],
                         ['', 'Port', session.connection.server.port],
                         ['', 'Encryption' if session.use_ssl else apply_style(ST_ERROR, 'Encryption'), 'SSL' if session.use_ssl else 'CLEARTEXT'],
                         ['', 'User', session.connection.user],
                         ['', 'Authentication', session.connection.authentication],
                         ['', '', ''],
                         ['Socket     ', 'Family', session.connection.socket.family],
                         ['', 'Type', session.connection.socket.type],
                         ['', 'Local', ' - '.join([str(el) for el in session.connection.socket.getsockname()])],
                         ['', 'Remote', ' - '.join([str(el) for el in session.connection.socket.getpeername()])],
                         ['', '', ''],
                         ['TLS        ', 'Status' if session.connection.server.ssl else apply_style(ST_ERROR, 'Status'), 'established' if session.connection.server.ssl else 'NOT established'],
                         ['', 'Version', session.connection.socket.version() if session.connection.server.ssl else '-'],
                         ['', 'Cipher', ' - '.join([str(el) for el in session.connection.socket.cipher()]) if session.connection.server.ssl else '-'],
                         ['Server info', 'Status' if session.connection.server.info else apply_style(ST_ERROR, 'Status'), 'No info returned by server' if not session.connection.server.info else 'Present - use "info server" to show'],
                         ['Schema info', 'Status' if session.connection.server.schema else apply_style(ST_ERROR, 'Status'), 'No schema returned by server' if not session.connection.server.schema else 'Present - use "info schema" to show']
                         ],
                        colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
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
                        table.append(['Standard', 'LDAP versions', sort_if_sequence(session.connection.server.info.supported_ldap_versions)])
                    if session.connection.server.info.supported_sasl_mechanisms:
                        table.append(['', 'SASL mechanisms', sort_if_sequence(session.connection.server.info.supported_sasl_mechanisms)])
                    if session.connection.server.info.vendor_name:
                        table.append(['', 'Vendor name', sort_if_sequence(session.connection.server.info.vendor_name)])
                    if session.connection.server.info.vendor_version:
                        table.append(['', 'Vendor version', sort_if_sequence(session.connection.server.info.vendor_version)])
                    if session.connection.server.info.alt_servers:
                        table.append(['', 'Alternate servers', sort_if_sequence(session.connection.server.info.alt_servers)])
                    if session.connection.server.info.naming_contexts:
                        table.append(['', 'Naming contexts', sort_if_sequence(session.connection.server.info.naming_contexts)])
                    if session.connection.server.info.schema_entry:
                        table.append(['', 'Schema entry', sort_if_sequence(session.connection.server.info.schema_entry)])
                    if session.connection.server.info.other:
                        table.append(['', '', ''])
                        # table = []
                        for i, key in enumerate(sort_if_sequence(session.connection.server.info.other.keys())):
                            table.append(['Other' if i == 0 else '', key, session.connection.server.info.other[key]])
                    build_table('Server (DSA) info',
                                [],
                                table,
                                colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
                                max_width=max_width,
                                level=0)

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
                        build_table('Server capabilities',
                                    ['type', 'name', 'OID', 'description'],
                                    table,
                                    sort=(0, sort_col),
                                    colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.object_classes.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.attribute_types.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.matching_rules.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.matching_rule_uses.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
                                    max_width=max_width)
                    else:
                        echo_detail('Matching rule uses', 'not present')

                    if session.connection.server.schema.dit_content_rules:
                        echo_empty_line()
                        build_table('DIT content rules',
                                    ['name', 'OID', 'obsolete', 'description'],
                                    [[list_to_string(element[1].name),
                                      element[1].oid,
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.dit_content_rules.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.dit_structure_rules.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
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
                                      apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                      element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                     for element in session.connection.server.schema.name_forms.items()],
                                    colums_style=[ST_DESCR, ST_VALUE, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
                                    max_width=max_width)
                    else:
                        echo_detail('Name forms', 'not present')

                    if session.connection.server.schema.ldap_syntaxes:
                        echo_empty_line()
                        temp_table = [[element[1].oid_info[2] if element[1].oid_info else element[1].oid,
                                       element[1].oid,
                                       apply_style(ST_ERROR, 'OBSOLETE') if element[1].obsolete else '',
                                       element[1].description if element[1].description else (str(element[1].oid_info[3]) if element[1].oid_info else '')]
                                      for element in session.connection.server.schema.ldap_syntaxes.items()]

                        for row in temp_table:
                            if '[OBSOLETE]' in row[0] and not row[2]:
                                row[2] = apply_style(ST_ERROR, 'OBSOLETE')
                                row[0] = row[0].replace('[OBSOLETE]', '')
                            if '[DEPRECATED]' in row[0] and not row[2]:
                                row[2] = apply_style(ST_ERROR, 'DEPRECATED')
                                row[0] = row[0].replace('[DEPRECATED]', '')
                        build_table('LDAP syntaxes',
                                    ['name', 'OID', 'obsolete', 'description'],
                                    temp_table,
                                    colums_style=[ST_DESCR, ST_VALUE, ST_ERROR, ST_TITLE],
                                    sort=sort_col,
                                    max_width=max_width)
                    else:
                        echo_detail('LDAP syntaxes', 'not present')

                    if session.connection.server.schema.other:
                        echo_empty_line()
                        table = []
                        for i, key in enumerate(sort_if_sequence(list(session.connection.server.schema.other.keys()))):
                            table.append(['Other' if i == 0 else '', key, session.connection.server.schema.other[key]])
                        build_table('',
                                    [],
                                    table,
                                    colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
                                    max_width=max_width,
                                    sort=sort_col,
                                    level=0)
        elif type != 'all':
            echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)

    session.done()


@click.command()
@click.pass_obj
@click.option('-s', '--scope', type=click.Choice(['base', 'level', 'subtree']), default='subtree', help='scope of search')
@click.option('-j', '--json', is_flag=True, help='format output as JSON')
@click.option('-l', '--ldif', is_flag=True, help='format output as LDIF')
@click.option('-i', '--listing', is_flag=True, help='format output as list')
@click.option('-p', '--paged', type=int, default=999, help='paged search size (0 to disable')
@click.option('-m', '--max-width', type=int, default=50, help='max column width')
@click.option('-o', '--operational', is_flag=True, help='request operational attributes')
@click.argument('base', type=click.STRING)
@click.argument('filter', required=False, default='(objectclass=*)')
@click.argument('attrs', nargs=-1, type=click.STRING)
def search(session, base, filter, attrs, scope, json, ldif, paged, listing, max_width, operational):
    """Search and return entries
    If no filter is specified the catch-all filter (objectclass=*) is used"""
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
            attrs = (filter,) + attrs
        try:
            if not paged:
                session.connection.search(base, search_filter, search_scope, attributes=attrs, get_operational_attributes=operational)
                responses = session.connection.response
            else:
                responses = session.connection.extend.standard.paged_search(base, search_filter, search_scope, attributes=attrs, get_operational_attributes=operational, paged_size=paged, generator=False)
        except LDAPInvalidFilterError:
            raise click.ClickException('invalid filter: %s' % filter)

        if responses:
            tot = 0
            table = []
            returned_attrs = CaseInsensitiveDict()
            for response in responses:
                if response['type'] == 'searchResEntry':
                    for attr in response['attributes']:
                        untagged_attr, _, _ = attr.partition(';')
                        # peserve original schema case
                        if session.connection.server.schema:
                            if untagged_attr in session.connection.server.schema.attribute_types:
                                for name in session.connection.server.schema.attribute_types[untagged_attr].name:
                                    if untagged_attr.lower() == name.lower():
                                        untagged_attr = name
                        returned_attrs[untagged_attr] = ''

            returned_attrs = sorted(list(returned_attrs.keys()))

            headers = ['#', 'DN'] + list(returned_attrs)
            other = []
            if json:
                click.echo(session.connection.response_to_json())
            elif ldif:
                click.echo(session.connection.response_to_ldif())
            else:
                for i, response in enumerate(responses, 1):
                    if response['type'] == 'searchResEntry':
                        tot = i
                        if listing:
                            display_response(i, response)
                        else:
                            if i != 1:
                                table.append(['', ''] + [''] * len(returned_attrs))
                            attr_list = []
                            for attr in returned_attrs:
                                if attr in response['attributes']:
                                    if isinstance(response['attributes'][attr], SEQUENCE_TYPES):
                                        attr_list.append(sort_if_sequence(response['attributes'][attr]))
                                    else:
                                        attr_list.append(response['attributes'][attr])
                                else:
                                    attr_list.append('')
                            table.append([str(i).rjust(len(str(len(responses)))), response['dn']] + attr_list)
                    else:
                        other.append(response)
                if not listing:
                    build_table('Response',
                                headers,
                                table,
                                colums_style=[ST_TITLE, ST_DESCR, ST_VALUE],
                                max_width=max_width,
                                level=0)

            if not json and not ldif:
                if other:
                    table = []
                    for i, response in enumerate(other):
                        if response['type'] == 'searchResRef':
                            table.append([str(i).rjust(len(str(len(responses)))), [to_unicode(uri) for uri in response['uri']]])
                    build_table('Search Referrals',
                                ['#', 'URI'],
                                table,
                                colums_style=[ST_TITLE, ST_VALUE],
                                level=0)

        else:
            echo_detail('Result', session.connection.result['description'] + ' - ' + session.connection.result['message'], error=True)
        session.done()
    else:
        echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)


cli.add_command(info)
cli.add_command(search)
