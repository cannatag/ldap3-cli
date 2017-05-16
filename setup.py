from setuptools import setup
from json import load

version_dict = load(open('_version.json', 'r'))
version = str(version_dict['version'])
author = str(version_dict['author'])
email = str(version_dict['email'])
license = str(version_dict['license'])
url = str(version_dict['url'])
description = str(version_dict['description'])
package_name = str(version_dict['package_name'])
package_folder = str(version_dict['package_folder'])
status = str(version_dict['status'])
print([i.strip() for i in open('requirements.txt').readlines()])

setup(
    name=package_name,
    version=version,
    py_modules=['ldap3cli'],
    install_requires=[i.strip() for i in open('requirements.txt').readlines()],
    license=license,
    author=author,
    author_email=email,
    description=description,
    keywords='python3 python2 ldap',
    url=url,
    classifiers=['Development Status :: 3 - Alpha',
                 'Environment :: Console',
                 'Intended Audience :: System Administrators',
                 'Operating System :: MacOS :: MacOS X',
                 'Operating System :: Microsoft :: Windows',
                 'Operating System :: POSIX :: Linux',
                 'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
                 'Programming Language :: Python',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 3',
                 'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP'],
    entry_points='''
       [console_scripts]
       ldap3=ldap3cli:cli
   '''
)
