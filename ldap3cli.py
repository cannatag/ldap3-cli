import click
from ldap3 import Server, Connection
from ldap3.core.exceptions import LDAPExceptionError

class Session(object):
    def __init__(self, host='localhost', port=389, use_ssl=False, dn=None, password=None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.dn = dn
        self.password = password
        self.server = None
        self.connection = None

    def echo(self):
        click.secho(self.host, fg='green')
        click.secho(str(self.port), fg='white')
        click.secho(str(self.use_ssl), fg='red', bold=True)
        click.secho(self.dn, fg='yellow')

    def connect(self):
        self.server = Server(self.host, self.port, self.use_ssl)
        self.connection = Connection(self.server, self.dn, self.password, raise_exceptions=True)
        try:
            self.connection.bind()
        except LDAPExceptionError as e:
            raise click.ClickException('unable to connect to %s on port %s - reason: %s' % (self.host, self.port,e))

@click.group()
@click.option('-h', '--host', default='localhost')
@click.option('-p', '--port', default=389)
@click.option('-d', '--dn')
@click.option('-w', '--password')
@click.option('-s', '--ssl', is_flag=True)
@click.pass_context
def cli(ctx, host, port, dn, password, ssl):
    """LDAP for humans"""
    ctx.obj = Session(host, port, ssl, dn, password)


@cli.command()
@click.pass_obj
def info(session):
    session.connect()
    session.echo()

if __name__ == '__main__':
    cli()
