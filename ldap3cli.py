import socket

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES, SIMPLE, NONE, DSA, SCHEMA, ALL
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPInvalidFilterError

bg = 'black'
fg = 'white'
error_fg = 'red'
error_bg = 'black'
title_fg = 'yellow'
title_bg = 'black'


def echo_title(string, level=0):
    click.secho('  ' * level + string, fg=title_fg, bg=title_bg)


def echo_detail(desc, value, error=False, level=1):
    click.secho('  ' * level + desc + ': ', fg=fg, bg=bg, nl=False)
    if error:
        click.secho(str(value), fg=error_fg, bg=error_bg, bold=True)
    else:
        click.secho(str(value), fg=fg, bg=bg, bold=True)


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
        self.debug =  debug
        self.server = Server(self.host, self.port, self.use_ssl, get_info=self.info)
        self.connection = Connection(self.server, self.user, self.password, authentication=authentication, raise_exceptions=False, collect_usage=self.usage)
        self.login_result=None

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
@click.option('-a', '--authentication', type=click.Choice(['ANONYMOUS', 'SIMPLE', 'SASL', 'NTLM']), default='SIMPLE', help='type of authentication')
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
@click.option('-s', '--schema', type=click.Choice(['NONE', 'ALL', 'OBJECTS', 'ATTRIBUTES']), default='NONE', help='display server schema')
def info(session, schema):
    """Bind and get info"""
    session.connect()
    echo_title('Connection info')
    click.secho('  Status: ', fg=fg, bg=bg, nl=False)
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
        echo_detail('Status', 'INFO returned by server')
        try:
            echo_detail('LDAP version', str(', '.join(session.connection.server.info.supported_ldap_versions)))
        except Exception:
            pass
        try:
            echo_detail('Vendor', str(', '.join(session.connection.server.info.vendor_name)) + '[' + str(', '.join(session.connection.server.info.vendor_version)) + ']')
        except Exception:
            pass
        try:
            echo_detail('Alternative servers', ', '.join(session.connection.server.info.alt_servers))
        except Exception:
            pass
        try:
            echo_detail('SASL mechanisms', ', '.join(session.connection.server.info.supported_sasl_mechanisms))
        except Exception:
            pass

    echo_title('Schema info')
    if not session.connection.server.schema:
        echo_detail('Status', 'NO SCHEMA returned by server', error=True)
    else:
        echo_detail('Status', 'SCHEMA returned by server')
        if schema == 'OBJECTS':
            echo_detail('Object Classes', session.server.schema.object_classes)
        elif schema == 'ATTRIBUTES':
            echo_detail('Object Classes', session.server.schema.attribute_types)
        elif schema == 'ALL':
            echo_detail('Object Classes', session.server.schema)

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
