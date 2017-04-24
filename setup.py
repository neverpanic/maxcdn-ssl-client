import os

from setuptools import setup

def read_deps(filename):
    absfilename = os.path.join(os.path.dirname(__file__), filename)
    with open(absfilename) as f:
        return [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]

setup(
    name='maxcdn-ssl-client',
    version='1.0',
    author='Clemens Lang',
    author_email='cal@macports.org',
    url='https://github.com/macports/maxcdn-ssl-client',
    description='MaxCDN API client to change SSL certificates in an automated'
                ' fashion.',
    packages=['maxcdn_ssl_client'],
    install_requires=read_deps('requirements.txt'),
    platforms='all',
    license='BSD',
    entry_points={
        'console_scripts': [
            'maxcdn-ssl-client = maxcdn_ssl_client.__main__:main'
        ]
    },
)
