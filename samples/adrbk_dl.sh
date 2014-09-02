#!/bin/sh
#
# Shellskript zum Starten Download des Adressbuchs


cd  ..

# Classpath aus dem Libverzeichnis automatisch zusammenbasteln
CP=$(echo -n bin$(for i in $(find lib -type f  -name "*.jar") ; do echo -n ":$i" ; done))

java -cp $CP de.mschwipps.CardDavAddressBookDownloader samples/kontakt.properties

