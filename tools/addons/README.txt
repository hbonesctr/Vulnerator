Vulnerator 2.0 add-ons
======================

Add-ons are optional extensions (for example dashboards or integrations). They are not part of Vulnerator
and none are included in this release.

To install an add-on, put its files in this folder: the main file ends in .AddOn.dll. An add-on that comes
with several files can have a folder of its own here. Then restart Vulnerator.

Settings > Integrations lists every add-on found and whether it loaded. An add-on that cannot be loaded is
skipped and the reason is written to the Vulnerator log; Vulnerator itself keeps working.

If Windows marks the files as downloaded from the internet, Vulnerator cannot load them: right-click each
file (or the .zip before extracting it), choose Properties, tick Unblock, and restart Vulnerator.

Add-ons see the data read-only and cannot change the database.
