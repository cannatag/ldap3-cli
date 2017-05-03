Command line utility for accessing LDAP servers

Usage: ldap3cli.py [OPTIONS] COMMAND [ARGS]...

  LDAP for humans

Options:
  -a, --authentication [ANONYMOUS|SIMPLE|SASL|NTLM]
                                  type of authentication
  -h, --host TEXT                 LDAP server hostname or ip address
  -p, --port INTEGER RANGE        LDAP server port
  -u, --user TEXT                 dn or user name
  -w, --password TEXT             password
  -W, --request-password          hidden prompt for password at runtime
  -s, --ssl                       establish a SSL/TLS connection
  -i, --server_info [NONE|DSA|SCHEMA|ALL]
                                  info requested to server
  -m, --metrics                   display usage metrics
  -d, --debug                     enable debug output
  --help                          Show this message and exit.

Commands:
  info    Bind and get info
  search  Search and return entries



Usage: ldap3cli.py info [OPTIONS] [TYPE]

  Bind and get info

Options:
  -j, --json                  format output as JSON
  -m, --max-width INTEGER     max column width
  -s, --sort [name|oid|type]  sorting column
  --help                      Show this message and exit.


Usage: ldap3cli.py search [OPTIONS] BASE [FILTER] [ATTRS]...

  Search and return entries

Options:
  -s, --scope [base|level|subtree]
                                  scope of search
  -j, --json                      format output as JSON
  -l, --ldif                      format output as LDIF
  --help                          Show this message and exit.

