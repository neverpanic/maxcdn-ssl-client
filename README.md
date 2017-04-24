MaxCDN SSL API client
=====================

Features
--------

List MaxCDN pull zones and their SSL status. Upload new SSL certificates for
MaxCDN pull zones and switch them to use the new certificate, while verifying
that all domains in the zone are also present in the SSL certificate.

Requirements
------------

`maxcdn-ssl-client` requires

- maxcdn ~= 0.0
- cryptography
- PyYAML


Setup
-----

To install `maxcdn-ssl-client`, use the included `setup.py`, for example using
`pip install` in a directory with the code. Copy the included
`maxcdn-ssl-client.yaml.example` file and enter your company alias and API
credentials.

Development
-----------

In a [virtualenv](http://www.virtualenv.org/), install the requirements:

    pip install maxcdn
	pip install cryptography
	pip install PyYAML
    pip install tox
    pip install -e .

Run pylint with

    tox -e pylint 

Changelog
---------

### 1.0

* Public release.

License
-------

This plugin is released under the BSD-2-Clause license.

It was initially written for [MacPorts](https://www.macports.org/)' services behind a CDN.
