# Introduction
libkeepass is a C++11 library for importing and exporting
[KeePass](http://keepass.info) password databases. It supports importing and
exporting from/to both the legacy KDB format, as well as the new KDBX format.

# Building
The following 3rd party libraries are required to build libkeepass:
* [OpenSSL](https://www.openssl.org/)
* [zlib](http://zlib.net)

For running the unit tests [googletest](https://code.google.com/p/googletest/)
is also required.

To build, simply do the following:
```sh
make -j8
```

to run the unit tests, do the following:
```sh
make test
```

# Using
The main library entry points are the *KdbFile* and *KdbxFile* classes. They
take care of both importing and exporting.

Example:
```cpp
keepass::Key key("password");

keepass::KdbxFile file;
std::unique_ptr<keepass::Database> db = file.Import("in.kdbx", key);

// Do some operations using the database object.

file.Export("out.kdbx", *db.get(), key);
```
