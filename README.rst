Command line utility for accessing LDAP servers

Usage: ldap3cli.py [OPTIONS] COMMAND [ARGS]...

  LDAP for humans

Options:
  -a, --authentication [anonymous|simple|sasl|ntlm]
                                  type of authentication
  -h, --host TEXT                 LDAP server hostname or ip address
  -p, --port INTEGER RANGE        LDAP server port
  -u, --user TEXT                 dn or user name
  -w, --password TEXT             password
  -W, --request-password          hidden prompt for password at runtime
  -s, --ssl                       establish a SSL/TLS connection
  -i, --server_info [none|dsa|schema|all]
                                  info requested to server
  -m, --metrics                   display usage metrics
  -d, --debug                     enable debug output
  --help                          Show this message and exit.

Commands:
  info    Bind and get info
  search  Search and return entries



Usage: ldap3cli.py info [OPTIONS] [TYPE]

  Bind and get info
  TYPE can be connection, server, schema or all

Options:
  -j, --json                  format output as JSON
  -m, --max-width INTEGER     max column width
  -s, --sort [name|oid|type]  sorting column
  --help                      Show this message and exit.


Usage: ldap3cli.py search [OPTIONS] BASE [FILTER] [ATTRS]...

  Search and return entries.
  If no filter is specified the catch-all filter
  (objectclass=*) is used

Options:
  -s, --scope [base|level|subtree]
                                  scope of search
  -j, --json                      format output as JSON
  -l, --ldif                      format output as LDIF
  -i, --listing                   format output as list
  -p, --paged INTEGER             paged search size (0 to disable
  -m, --max-width INTEGER         max column width
  -o, --operational               request operational attributes
  --help                          Show this message and exit.

