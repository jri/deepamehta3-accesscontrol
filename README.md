
DeepaMehta 3 Accounts Plugin
============================

Restricts access to DeepaMehta 3 by putting a login dialog at application start.
Accounts can be created and modified by the user. One account is pre-configured.

Note: there is no access control mechanism with individual permissions yet.
This plugin just restricts a DeepaMehta 3 installation to a set of well-known users.
Each user, once logged in, has access to everything.


Requirements
------------

* A DeepaMehta 3 installation  
  <http://github.com/jri/deepamehta3>


Installation
------------


Usage
-----

1.  Visit DeepaMehta 3 in your webbrowser (resp. press reload):
        http://localhost:5984/deepamehta3-db/_design/deepamehta3/index.html
    A login dialog will appear.

2.  Login as *admin*. Leave the *Password* field empty.

### Create another account ###

1.  Accounts are ordinary DeepaMehta 3 topics. You'll find an additional topic type *Account*
    in the type menu (next to the *Create* button). Create an account.

2.  Fill in the *Username* and *Password* fields and click *Save*. The new account is active from now on.
    (To test it return to the login dialog by pressing the browser's *Reload* button.)

### Modify an account ###

1.  Search for the account (e.g. by fulltext or time search) and reveal it.

2.  Click the *Edit* button and make your changes, e.g. change the password, and click *Save*.


Updating
--------

1.  Go to your DeepaMehta 3 installation directory:
        cd deepamehta3

2.  Update DeepaMehta 3 Accounts Plugin:
        couchapp vendor update dm3-accounts

3.  Copy additional stuff:
        cp -r vendor/dm3-accounts/views/dm3-accounts views

4.  Upload changes to CouchDB:
        couchapp push http://localhost:5984/deepamehta3-db


Version History
---------------

**v0.3** -- Mar 6, 2010

* Topic type "Account" got an icon
* Account "Notes" is a rich text field
* Compatible with DeepaMehta 3 v0.3

**v0.2** -- Dec 1, 2009

* Basic functionality
* Requires DeepaMehta 3 v0.2


------------
Jörg Richter  
Mar 6, 2009
