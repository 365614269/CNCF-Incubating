=================
libvirt-go-module
=================

.. image:: https://gitlab.com/libvirt/libvirt-go-module/badges/master/pipeline.svg
   :target: https://gitlab.com/libvirt/libvirt-go-module/pipelines
   :alt: Build Status
.. image:: https://img.shields.io/static/v1?label=godev&message=reference&color=00add8
   :target: https://pkg.go.dev/libvirt.org/go/libvirt
   :alt: API Documentation

Go bindings for libvirt.

Make sure to have ``libvirt-dev`` package (or the development files
otherwise somewhere in your include path)


Version Support
===============

The libvirt go package provides API coverage for libvirt versions
from 1.2.0 onwards, through conditional compilation of newer APIs.

By default the binding will support APIs in libvirt.so, libvirt-qemu.so
and libvirt-lxc.so. Coverage for the latter two libraries can be dropped
from the build using build tags 'libvirt_without_qemu' or 'libvirt_without_lxc'
respectively.

The library expects to be used with Go >= 1.11 with Go modules active.
Older versions are no longer tested, nor is usage without Go modules.

Development status
==================

The Go API is considered to be production ready and aims to be kept
stable across future versions. Note, however, that the following
changes may apply to future versions:

* Existing structs can be augmented with new fields, but no existing
  fields will be changed / removed. New fields are needed when libvirt
  defines new typed parameters for various methods

* Any method with an 'flags uint32' parameter will have its parameter
  type changed to a specific typedef, if & when the libvirt API defines
  constants for the flags. To avoid breakage, always pass a literal
  '0' to any 'flags uint32' parameter, since this will auto-cast to
  any future typedef that is introduced.

Please see the `VERSIONING <VERSIONING.rst>`_ file for information
about release schedule and versioning scheme.


Documentation
=============

* `API documentation for the bindings <https://pkg.go.dev/libvirt.org/go/libvirt>`_
* `API documentation for libvirt <https://libvirt.org/html/index.html>`_


Contributing
============

The libvirt project aims to add support for new APIs to libvirt-go-module
as soon as they are added to the main libvirt C library. If you
are submitting changes to the libvirt C library API, please submit
a libvirt-go-module change at the same time. Bug fixes and other
improvements to the libvirt-go-module library are welcome at any time.

For more information, see the `CONTRIBUTING <CONTRIBUTING.rst>`_
file.


Testing
=======

The core API unit tests are all written to use the built-in
test driver (test:///default), so they have no interaction
with the host OS environment.

Coverage of libvirt C library APIs / constants is verified
using automated tests. These can be run by passing the 'api'
build tag. eg  go test -tags api

For areas where the test driver lacks functionality, it is
possible to use the QEMU or LXC drivers to exercise code.
Such tests must be part of the 'integration_test.go' file
though, which is only run when passing the 'integration'
build tag. eg  go test -tags integration

In order to run the unit tests, libvirtd should be configured
to allow your user account read-write access with no passwords.
This can be easily done using polkit config files

::

   # cat > /etc/polkit-1/localauthority/50-local.d/50-libvirt.pkla  <<EOF
   [Passwordless libvirt access]
   Identity=unix-group:berrange
   Action=org.libvirt.unix.manage
   ResultAny=yes
   ResultInactive=yes
   ResultActive=yes
   EOF

(Replace 'berrange' with your UNIX user name).

Two of the integration tests also requires that libvirtd is
listening for TCP connections on localhost, with sasl auth
This can be setup by editing /etc/libvirt/libvirtd.conf to
set

::

   listen_tls=0
   listen_tcp=1
   auth_tcp=sasl
   listen_addr="127.0.0.1"

and then start libvirtd with the --listen flag (this can
be set in /etc/sysconfig/libvirtd to make it persistent).

sasl authentication must be configured_ to use ``scram-sha-256``,
and the needed sasl modules must be installed on the system.

.. _configured: https://libvirt.org/auth.html#ACL_server_sasl

Then create a sasl user

::

   $ saslpasswd2 -a libvirt user

and enter "pass" as the password.
