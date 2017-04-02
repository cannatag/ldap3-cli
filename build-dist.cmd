call act.cmd
rd dist build ldap3_cli.egg-info /S /Q
python setup.py clean
python setup.py build sdist --format=gztar
python setup.py build bdist_wininst
python setup.py build bdist_wheel --universal
