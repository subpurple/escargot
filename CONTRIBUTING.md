# Developer Guide

## New Developers

Contributions are welcome via MR (Merge Requests). You don't need to request project member access; clone the repo instead!

## Setup 

- you will need python 3.6+
- ([MSYS2](https://github.com/valtron/llvm-stuff/wiki/Set-up-Windows-dev-environment-with-MSYS2) env recommended for Windows users)
- `cd` into `msn-server`
- install dependencies: `python -m pip install -r requirements.txt`
- create `settings_local.py` and set debug options:
	```
	DEBUG = True
	DEBUG_MSNP = True
	DEBUG_HTTP_REQUEST = True
	```
	- if you want to enable support for other frontends, set the following options:
		- YMSG:
		```
		ENABLE_FRONT_YMSG = True
		DEBUG_YMSG = True
		```
		- IRC:
		```
		ENABLE_FRONT_IRC = True
		```
- run `python script/dbcreate.py`; if you get `ModuleNotFoundError: No module named '...'`, add `export PYTHONPATH=".;$PYTHONPATH"` in your `.bashrc`
- run `python script/dummydata.py` (creates a few dummy accounts, passwords are all "123456")

- to create users, run `python script/user.py -h` for instructions

## MSN

- for 4.7.2009 and 4.7.3001, use a **clean** install, and in your `HOSTS` add:
	```
	127.0.0.1 m1.escargot.log1p.xyz
	127.0.0.1 messenger.hotmail.com
	127.0.0.1 gateway.messenger.hotmail.com
	127.0.0.1 nexus.passport.com
	```
- for 5.0 - 7.5, use a **patched** install, and in your `HOSTS` add `127.0.0.1 m1.escargot.log1p.xyz`
	- **(6.0+ only):** add `127.0.0.1 ebyrdromegactcsmsn.log1p.xyz` in your `HOSTS`
- for WLM:
	- 8.1.0178 and 8.5.1302: use a **patched** install, and in your `HOSTS` add:
	```
	127.0.0.1 m1.escargot.log1p.xyz
	127.0.0.1 ebyrdromegactcsmsn.log1p.xyz
	127.0.0.1 etkrdrstmsn.log1p.xyz
	127.0.0.1 eowsmsgrmsn.log1p.xyz
	127.0.0.1 ersih.log1p.xyz
	```
	- 9.0.1407.1107 - 14.0.8117.0416:
		- use a **clean** install of the Messenger MSI:
			- 9.0.1407.1107: https://archive.org/download/MsnMessengerClients2/Windows%20Live%20Messenger%209.0.1407.1107%20%28English%20-%20United%20States%29.zip
			- 14.0.8117.0416: https://archive.org/download/MsnMessengerClients2/Windows%20Live%20Messenger%2014.0.8117.0416%20%28English%29.zip
		
		- **(14.x only):** install the [Windows Live Communications Platform](http://messenger.jonathankay.com/redir/w3qfe2update/contacts.asp)
		
		- in your `HOSTS` add:
		```
		127.0.0.1 m1.escargot.log1p.xyz
		127.0.0.1 messenger.hotmail.com
		127.0.0.1 login.live.com
		127.0.0.1 gateway.messenger.hotmail.com
		127.0.0.1 byrdr.omega.contacts.msn.com
		127.0.0.1 config.messenger.msn.com
		127.0.0.1 tkrdr.storage.msn.com
		127.0.0.1 ows.messenger.msn.com
		127.0.0.1 rsi.hotmail.com
		```
	
	(Note about the `127.0.0.1 login.live.com` entry: **BE SURE TO REMOVE IT OR COMMENT IT OUT AFTER TESTING OR ELSE YOU WON'T BE ABLE TO LOG ON TO ANY OFFICIAL MICROSOFT SERVICES!!**)

## Yahoo!

- for version 5.5, use a **clean** install and patch the following registry values:
	- `HKEY_CURRENT_USER\SOFTWARE\Yahoo\Pager\socket server` -> `localhost`
	- `HKEY_CURRENT_USER\SOFTWARE\Yahoo\Pager\FileTransfer\Server Name` -> `localhost`

- and also, in your `HOSTS`, add:
	```
	127.0.0.1 scs.msg.yahoo.com
	127.0.0.1 rd.yahoo.com
	127.0.0.1 insider.msg.yahoo.com
	127.0.0.1 us.i1.yimg.com
	127.0.0.1 chat.yahoo.com
	127.0.0.1 filetransfer.msg.yahoo.com
	127.0.0.1 yahoo-ftstore.log1p.xyz
	```

- run `python dev` to start the dev server

The **first time** you run `python dev`, a root certificate `DO_NOT_TRUST_DevTLS_Escargot.crt` is created in `.devtls_cache`,
it tells you to install it, and exits. To install (on Windows):

- double click the certificate
- click "Install Certificate..."
- select "Current User" for "Store Location"
- select "Place all certificates in the following store", click "Browse...", and select "Trusted Root Certification Authorities"
- click "Next" and then "Finish"

Now run `python dev` again, and it should start all the services: NB, SB, http, https.
When you visit a domain that's redirected to `127.0.0.1` using https, the dev server automatically creates a certificate.

When you run MSN now, assuming it's patched, all traffic will be going to your local dev server.
However, MSN <= 6.2 still cache the IP of the server in the registry, so you might need to clear that out
if you're testing those versions. It's located:

- MSN 1.0 - 4.7: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\MessengerService\Server`
- MSN 5.0 - 6.2: `HKEY_CURRENT_USER\SOFTWARE\Microsoft\MSNMessenger\Server`

All generated certificates expire after 30 days for "security" purposes (i.e. I didn't
set it to a long period of time so as to not open anyone up to... vulnerabilities...
if they forget to uninstall the root certificate).

## Typechecking/MyPy

Take advantage of [mypy](https://mypy-lang.org) by adding type annotations.
Run `mypy dev` to typecheck, and do your best to ensure your commits contain no typechecking errors.

There should be no typechecking errors (i.e. `mypy dev` should not output anything) if you are submitting an MR
or pushing to remote.

## Testing

There are no actual tests right now. Contributions to the tests are greatly appreciated :p

Run all tests:

```
python tests
```

Run a specific test:

```
python tests tests/auth_service.py::test_multiple_in_order
```
