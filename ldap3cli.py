import socket
from operator import itemgetter

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES, SIMPLE, NONE, DSA, SCHEMA, ALL
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

sorting = {'name': 0,
           'oid': 1,
           'type': 2}


def list_to_string(list_object):
    if not isinstance(list_object, SEQUENCE_TYPES):
        return list_object

    r = ''
    for element in list_object:
        r += (list_to_string(element) if isinstance(element, SEQUENCE_TYPES) else str(element)) + ', '

    return r[:-2] if r else ''


def build_table(name, heading, rows, sort=0):
    if rows:
        lengths = dict()
        for col, _ in enumerate(heading):
            lengths[col] = max([len(row[col]) for row in [heading] + rows])
        table = [' - '.join([element.ljust(lengths[col]) for col, element in enumerate(heading)]),
                 ' - '.join([''.ljust(lengths[col], '=') for col, element in enumerate(heading)])]
        for row in sorted(rows, key=itemgetter(sort)):
            table.append(' - '.join([element.ljust(lengths[col]) for col, element in enumerate(row)]))
    else:
        table = ['']
    echo_detail_multiline(name, table)


def echo_title(string, level=0):
    click.secho('  ' * level + string, fg=title_fg, bg=title_bg, bold=title_bold)


def echo_detail(desc, value, error=False, level=1):
    if value:
        if desc:
            click.secho('  ' * level + desc + (': ' if not desc.isspace() else '  '), fg=desc_fg, bg=desc_bg, bold=desc_bold, nl=False)
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
            echo_detail(desc, line)
            first = True
        else:
            echo_detail(' ' * len(desc), line)


class Session(object):
    def __init__(self, host, port, use_ssl, user, password, authentication, get_info, usage, debug):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.user = user
        self.password = password
        self.server = None
        self.connection = None
        self.authentication = authentication
        self.info = get_info
        self.usage = usage
        self.debug = debug
        self.server = Server(self.host, self.port, self.use_ssl, get_info=self.info)
        self.connection = Connection(self.server, self.user, self.password, authentication=authentication, raise_exceptions=False, collect_usage=self.usage)
        self.login_result = None

    def done(self):
        self.connection.unbind()
        if self.usage:
            echo_title('Usage metrics')
            echo_detail('Usage', self.connection.usage)

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
@click.option('-a', '--authentication', type=click.Choice(['ANONYMOUS', 'SIMPLE', 'SASL', 'NTLM']), help='type of authentication')
@click.option('-h', '--host', default='localhost', help='LDAP server hostname or ip address')
@click.option('-p', '--port', type=click.IntRange(0, 65535), help='LDAP server port')
@click.option('-u', '--user', help='dn or user name')
@click.option('-w', '--password', help='password')
@click.option('-W', '--request-password', is_flag=True, help='hidden prompt for password at runtime')
@click.option('-s', '--ssl', is_flag=True, help='establish a SSL/TLS connection')
@click.option('-i', '--server_info', type=click.Choice(['NONE', 'DSA', 'SCHEMA', 'ALL']), default='ALL', help='info requested to server')
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
@click.option('-s', '--sort', type=click.Choice(['name', 'oid', 'type']), default='name', help='sorting column')
@click.argument('type', type=click.Choice(['connect', 'server', 'schema', 'all']), default='connect')
def info(session, type, json, sort):
    """Bind and get info"""
    session.connect()
    if type in ['connect', 'all']:
        echo_title('Connection info')
        if session.connection.bound:
            echo_detail('Status', 'valid')
        else:
            echo_detail('Status', 'NOT valid [' + str(session.login_result) + ']', error=True)
        echo_detail('Host', session.connection.server.host)
        echo_detail('Port', session.connection.server.port)
        echo_detail('Encryption', ' session is using SSL' if session.use_ssl else ' session is in CLEARTEXT')
        echo_detail('User', session.connection.user)
        echo_detail('Authentication', session.connection.authentication)
        echo_title('Socket info')
        echo_detail('Family', session.connection.socket.family)
        echo_detail('Type', session.connection.socket.type)
        echo_title('Endopoints', 1)
        echo_detail('Local', session.connection.socket.getsockname(), level=2)
        echo_detail('Remote', session.connection.socket.getpeername(), level=2)
        echo_title('TLS info')
        if session.connection.server.ssl:
            echo_detail('TLS status', 'established')
            echo_detail('TLS version', session.connection.socket.version())
            echo_detail('TLS cipher', session.connection.socket.cipher())
        else:
            echo_detail('TLS status', 'NOT established', error=True)
        echo_title('Server info')
        if not session.connection.server.info:
            echo_detail('Status', 'NO INFO returned by server', error=True)
        else:
            echo_detail('Status', 'INFO returned by server - use "info server" to show')
        echo_title('Schema info')
        if not session.connection.server.schema:
            echo_detail('Status', 'NO SCHEMA returned by server', error=True)
        else:
            echo_detail('Status', 'SCHEMA returned by server - use "info schema" to show')

    if type in ['server', 'all']:
        if json:
            echo_detail_multiline('', session.connection.server.info.to_json())
        else:
            echo_title('Server info')
            if not session.connection.server.info:
                echo_detail('Status', 'NO INFO returned by server', error=True)
            else:
                if session.connection.server.info.supported_ldap_versions:
                    echo_detail('Supported LDAP versions', ' - '.join(sorted(session.connection.server.info.supported_ldap_versions if isinstance(session.connection.server.info.supported_ldap_versions, SEQUENCE_TYPES) else session.connection.server.info.supported_ldap_versions)))
                if session.connection.server.info.supported_sasl_mechanisms:
                    echo_detail('Supported SASL mechanisms', ' - '.join(sorted(session.connection.server.info.supported_sasl_mechanisms) if isinstance(session.connection.server.info.supported_sasl_mechanisms, SEQUENCE_TYPES) else session.connection.server.info.supported_sasl_mechanisms))
                if session.connection.server.info.vendor_name:
                    echo_detail('Vendor name', ' - '.join(session.connection.server.info.vendor_name) if isinstance(session.connection.server.info.vendor_name, SEQUENCE_TYPES) else session.connection.server.info.vendor_name)
                if session.connection.server.info.vendor_version:
                    echo_detail('Vendor version', ' - '.join(session.connection.server.info.vendor_version) if isinstance(session.connection.server.info.vendor_version, SEQUENCE_TYPES) else session.connection.server.info.vendor_version)
                if session.connection.server.info.alt_servers:
                    echo_detail('Alternate servers', ' - '.join(sorted(session.connection.server.info.alt_servers)) if isinstance(session.connection.server.info.alt_servers, SEQUENCE_TYPES) else session.connection.server.info.alt_servers)
                if session.connection.server.info.naming_contexts:
                    echo_detail('Naming contexts', ' - '.join(sorted(session.connection.server.info.naming_contexts)) if isinstance(session.connection.server.info.naming_contexts, SEQUENCE_TYPES) else session.connection.server.info.naming_contexts)
                if session.connection.server.info.supported_controls:
                    echo_detail_multiline('Supported controls', [element[0] + (element[2] if element[2] else '') + (element[3] if element[3] else '') for element in session.connection.server.info.supported_controls])
                if session.connection.server.info.supported_extensions:
                    echo_detail_multiline('Supported extensions', [element[0] + (element[2] if element[2] else '') + (element[3] if element[3] else '') for element in session.connection.server.info.supported_extensions])
                if session.connection.server.info.supported_features:
                    echo_detail_multiline('Supported features', [element[0] + (element[2] if element[2] else '') + (element[3] if element[3] else '') for element in session.connection.server.info.supported_features])
                if session.connection.server.info.schema_entry:
                    echo_detail('Schema entry', ' - '.join(session.connection.server.info.schema_entry) if isinstance(session.connection.server.info.schema_entry, SEQUENCE_TYPES) else session.connection.server.info.schema_entry)
                if session.connection.server.info.other:
                    echo_title('Other info')
                    for key, value in session.connection.server.info.other.items():
                        echo_detail(key, ' - '.join(value) if isinstance(value, SEQUENCE_TYPES) else value)
    if type in ['schema', 'all']:
        if json:
            echo_detail_multiline('', session.connection.server.schema.to_json())
            print(len(session.connection.server.schema.to_json()))
        else:
            echo_title('Schema info')
            if not session.connection.server.schema:
                echo_detail('Status', 'NO SCHEMA returned by server', error=True)
            else:
                if session.connection.server.schema.object_classes:
                    build_table('Object classes',
                                ['name', 'OID', 'type (kind)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  element[1].kind,
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.object_classes.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('Object classes', 'not present')

                if session.connection.server.schema.attribute_types:
                    build_table('Attribute types',
                                ['name', 'OID', 'type (syntax)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  decode_syntax(element[1].syntax)[2] if decode_syntax(element[1].syntax)[2] != 'Unknown' else element[1].syntax,
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.attribute_types.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('Attribute types', 'not present')

                if session.connection.server.schema.matching_rules:
                    build_table('Matching rules',
                                ['name', 'OID', 'type (syntax)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  list_to_string(element[1].syntax),
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.matching_rules.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('Matching rules', 'not present')

                if session.connection.server.schema.matching_rule_uses:
                    build_table('Matching rule uses',
                                ['name', 'OID', 'type (apply to)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  list_to_string(element[1].apply_to),
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.matching_rule_uses.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('Matching rule uses', 'not present')

                if session.connection.server.schema.dit_content_rules:
                    build_table('DIT content rules',
                                ['name', 'OID', 'type (auxiliary class)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  list_to_string(element[1].auxiliary_classes),
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.dit_content_rules.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('DIT content rules', 'not present')

                if session.connection.server.schema.dit_structure_rules:
                    build_table('DIT structure rules',
                                ['name', 'OID', 'type (name form)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  list_to_string(element[1].name_form),
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.dit_structure_rules.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('DIT structure rules', 'not present')

                if session.connection.server.schema.name_forms:
                    build_table('Name forms',
                                ['name', 'OID', 'type (object class)', 'obsolete', 'description'],
                                [[list_to_string(element[1].name),
                                  element[1].oid,
                                  list_to_string(element[1].object_class),
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.name_forms.items()],
                                sort=sorting[sort])
                else:
                    echo_detail('Name forms', 'not present')

                if session.connection.server.schema.ldap_syntaxes:
                    print(session.connection.server.schema.ldap_syntaxes[list(session.connection.server.schema.ldap_syntaxes.keys())[0]])
                    temp_table = [[element[1].oid_info[2] if element[1].oid_info else element[1].oid,
                                  element[1].oid,
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if element[1].obsolete else ''),
                                  (element[1].description if element[1].description else '')]
                                 for element in session.connection.server.schema.ldap_syntaxes.items()]

                    build_table('LDAP syntaxes',
                                ['name', 'OID', 'obsolete', 'description'],
                                [[element[0],
                                  element[1],
                                  (click.style('OBSOLETE', fg=error_fg, bg=error_bg, bold=error_bold) if '[OBSOLETE]' in element[0] else element[2]),
                                  element[3]]
                                 for element in temp_table],
                                sort=sorting[sort])
                else:
                    echo_detail('LDAP syntaxes', 'not present')

                if session.connection.server.schema.other:
                    echo_detail('Other info', '')
                    for key, value in session.connection.server.schema.other.items():
                        echo_detail(key, ' - '.join(value) if isinstance(value, SEQUENCE_TYPES) else value, level=2)
    session.done()


@cli.command()
@click.pass_obj
@click.option('-s', '--scope', type=click.Choice(['BASE', 'LEVEL', 'SUBTREE']), default='SUBTREE', help='scope of search')
@click.argument('base', type=click.STRING)
@click.argument('filter', required=False, default='(objectclass=*)')
@click.argument('attrs', nargs=-1, type=click.STRING)
def search(session, base, filter, attrs, scope):
    """Search and return entries"""
    session.connect()
    try:
        session.connection.search(base, filter, scope, attributes=attrs)
    except LDAPInvalidFilterError:
        raise click.ClickException('invalid filter: %s' % filter)
    for e in session.connection.entries:
        click.secho(str(e))


if __name__ == '__main__':
    cli()
