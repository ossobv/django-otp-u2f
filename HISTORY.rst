=======
History
=======

0.2.5 (2022-06-09)
------------------

* Depend on fido<1 because >=1 has breaking changes.


0.2.4 (2022-01-13)
------------------

* Allow form submission with keyboard.


0.2.3 (2021-12-24)
------------------

* Delay key registration until the button is pressed to allow the user
  to change the name of the key during registration.


0.2.2 (2021-12-24)
------------------

* Restore compatibility with python 3.6.


0.2.1 (2021-12-23)
------------------

* Fix missing import.


0.2.0 (2021-12-23)
------------------

* Switch to the Web Authentication API.


0.1.6 (2021-07-09)
------------------

* Fix device verification to return the device used to sign the
  challenge instead of the device used to initiate the challenge.
* Switch to setuptools_scm for automatic git versioning.
* Move package data to setup.cfg.
* Switch django TestCase to pytest fixtures.
* Add Python 3.9 and Django 3.2 to the support matrix.
* Move test dependencies to the otp_u2f[test] extra.
* Switch to PEP517 package builder.
* Exclude tests from package.


0.1.5 (2020-10-23)
------------------

* Update to replace botched release :-)


0.1.4 (2020-10-23)
------------------

* Fix deprecation warnings in preparation of Django 4.
* Fix javascript logging call.


0.1.3 (2019-11-07)
------------------

* Update minimum dependencies.
* Add test for current authentication method.


0.1.2 (2019-11-07)
------------------

* Use package setup whilelist.
* Add original author.
* Remove python 2 classifiers.


0.1.1 (2019-11-05)
------------------

* First release on PyPI.
