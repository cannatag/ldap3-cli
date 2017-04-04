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

    def echo(self):
        click.secho('HOST ' + self.host, fg='black', bg='white', nl=False)
        click.secho(' PORT ' + str(self.port), fg='black', bg='white', nl=False)
        click.secho(' <SSL>' if self.use_ssl else ' <CLEARTEXT>', fg='red', bold=True, bg='white', nl=False)
        click.secho(' USER: ' + str(self.user), fg='yellow', bg='white')

        if self.debug:
            click.secho(str(self.connection))


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

@click.group()
@click.option('-h', '--host', default='localhost')
@click.option('-p', '--port', default=389, type=click.IntRange(0, 65535))
@click.option('-u', '--user')
@click.option('-w', '--password')
@click.option('-W', '--request-password', is_flag=True)
@click.option('-s', '--ssl', is_flag=True)
@click.option('-d', '--debug', is_flag=True)

@click.pass_context
def cli(ctx, host, port, user, password, ssl, debug, request_password):
    """LDAP for humans"""
    if request_password and not password:
        password = click.prompt('Password <will not be shown>', hide_input=True, type=click.STRING)
    ctx.obj = Session(host, port, ssl, user, password, debug)


@cli.command()
@click.pass_obj
def info(session):
    """Bind and get info"""
    session.connect()
    session.echo()

@cli.command()
@click.pass_obj
@click.option('-s', '--scope', type=click.Choice(['BASE', 'LEVEL', 'SUBTREE']), default='SUBTREE')
@click.option('-b', '--base', type=click.STRING)
@click.option('-f', '--filter', default='(objectclass=*)')
@click.option('-a', '--attr', required=False, nargs=-1, type=click.STRING)
def search(session, base, filter, attributes, scope):
    """Search and return entries"""
    session.connect()
    try:
        session.connection.search(base, filter, scope, attributes=attributes)
    except LDAPInvalidFilterError:
        raise click.ClickException('invalid filter: %s' % filter)
    for e in session.connection.entries:
        click.secho(str(e))

if __name__ == '__main__':
    cli()
