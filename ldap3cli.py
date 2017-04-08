import socket

import click
from ldap3 import Server, Connection, SEQUENCE_TYPES
from ldap3.core.exceptions import LDAPExceptionError, LDAPSocketOpenError, LDAPInvalidFilterError


class Session(object):
    def __init__(self, host='localhost', port=389, use_ssl=False, user=None, password=None, debug=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.user = user
        self.password = password
        self.server = None
        self.connection = None
        self.debug =  debug
        self.server = Server(self.host, self.port, self.use_ssl)
        self.connection = Connection(self.server, self.user, self.password, raise_exceptions=False)
        self.login_result=None

    def echo(self):
        bg = 'black'
        fg = 'white'
        click.secho('HOST ' + self.host, fg=fg, bg=bg, bold=True, nl=False)
        click.secho(' - PORT ' + str(self.port), fg=fg, bg=bg, bold=True, nl=False)
        click.secho(' - session is using SSL' if self.use_ssl else ' - session is in CLEARTEXT', fg=fg, bold=True, bg=bg, nl=False)
        click.secho(' - USER: ' + str(self.user), fg=fg, bg=bg, bold=True, nl=False)
        if self.connection.bound:
            click.secho(' - STATUS: valid', fg=fg, bg=bg, bold=True)
        else:
            click.secho(' - STATUS: NOT valid', fg='red', bg=bg, bold=True, nl=False)
            click.secho(' [REASON: ' + str(self.login_result) + ']', fg='red', bg=bg, bold=True)
        if self.debug:
            click.secho(str(self.connection))
        click.secho('Socket info:')
        click.secho('Family: ', fg=fg, bg=bg, nl=False)
        click.secho(str(self.connection.socket.family), fg=fg, bg=bg, bold=True)
        click.secho('Type: ', fg=fg, bg=bg, nl=False)
        click.secho(str(self.connection.socket.type), fg=fg, bg=bg, bold=True)
        click.secho('Local: ', fg=fg, bg=bg, nl=False)
        click.secho(str(self.connection.socket.getsockname()), fg=fg, bg=bg, bold=True)
        click.secho('Remote: ', fg=fg, bg=bg, nl=False)
        click.secho(str(self.connection.socket.getpeername()), fg=fg, bg=bg, bold=True)
        if self.connection.server.ssl:
            click.secho('TLS version: ', fg=fg, bg=bg, nl=False)
            click.secho(str(self.connection.socket.version()), fg=fg, bg=bg, bold=True)
            click.secho('TLS cipher: ', fg=fg, bg=bg, nl=False)
            click.secho(str(self.connection.socket.cipher()), fg=fg, bg=bg, bold=True)

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
@click.option('-h', '--host', default='localhost', help='LDAP server hostname or ip address')
@click.option('-p', '--port', type=click.IntRange(0, 65535), help='LDAP server port')
@click.option('-u', '--user', help='dn or user name')
@click.option('-w', '--password', help='password')
@click.option('-W', '--request-password', is_flag=True, help='hidden prompt for password at runtime')
@click.option('-s', '--ssl', is_flag=True, help='establish a SSL/TLS connection')
@click.option('-d', '--debug', is_flag=True, help='enable debug output')


@click.pass_context
def cli(ctx, host, port, user, password, ssl, debug, request_password):
    """LDAP for humans"""
    if request_password and not password:
        password = click.prompt('Password <will not be shown>', hide_input=True, type=click.STRING)
    if ssl and not port:
        port = 636
    elif not port:
        port = 389
    ctx.obj = Session(host, port, ssl, user, password, debug)


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
