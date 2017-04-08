import socket

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES, SIMPLE, ALL
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
    def __init__(self, host='localhost', port=389, use_ssl=False, user=None, password=None, authentication=SIMPLE, debug=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.user = user
        self.password = password
        self.server = None
        self.connection = None
        self.authentication = authentication
        self.debug =  debug
        self.server = Server(self.host, self.port, self.use_ssl, get_info=ALL)
        self.connection = Connection(self.server, self.user, self.password, authentication=authentication, raise_exceptions=False)
        self.login_result=None

    def echo(self):

        echo_title('Connection info')
        click.secho('  Status: ', fg=fg, bg=bg, nl=False)
        if self.connection.bound:
            click.secho('valid', fg=fg, bg=bg, bold=True)
        else:
            click.secho('NOT valid', fg=fg, bg=bg, bold=True, nl=False)
            click.secho(' [REASON: ' + str(self.login_result) + ']', error=True)
        echo_detail('Host', self.connection.server.host)
        echo_detail('Port', self.connection.server.port)
        echo_detail('Encryption', ' session is using SSL' if self.use_ssl else ' session is in CLEARTEXT')
        echo_detail('User', self.connection.user)
        echo_detail('Authentication', self.connection.authentication)
        echo_title('Socket info')
        echo_detail('Family', self.connection.socket.family)
        echo_detail('Type', self.connection.socket.type)
        echo_title('Endopoints', 1)
        echo_detail('Local', self.connection.socket.getsockname(), level=2)
        echo_detail('Remote', self.connection.socket.getpeername(), level=2)
        echo_title('TLS info')
        if self.connection.server.ssl:
            echo_detail('TLS status', 'established')
            echo_detail('TLS version', self.connection.socket.version())
            echo_detail('TLS cipher', self.connection.socket.cipher())
        else:
            echo_detail('TLS status', 'NOT established', error=True)
        echo_title('Server info')
        try:
            echo_detail('LDAP version', self.connection.server.info.supported_ldap_versions)
        except Exception:
            pass
        try:
            echo_detail('Vendor', str(self.connection.server.info.vendor_name) + '[' + str(self.connection.server.info.vendor_version) + ']')
        except Exception:
            pass

        echo_detail('Alternative servers', self.connection.server.info.alt_servers)
        echo_detail('SASL mechanisms', self.connection.server.info.supported_sasl_mechanisms)



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
@click.option('-d', '--debug', is_flag=True, help='enable debug output')
@click.pass_context
def cli(ctx, host, port, user, password, ssl, debug, request_password, authentication):
    """LDAP for humans"""
    if request_password and not password:
        password = click.prompt('Password <will not be shown>', hide_input=True, type=click.STRING)
    if ssl and not port:
        port = 636
    elif not port:
        port = 389
    ctx.obj = Session(host, port, ssl, user, password, authentication, debug)


@cli.command()
@click.pass_obj
def info(session):
    """Bind and get info"""
    session.connect()
    session.echo()


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
