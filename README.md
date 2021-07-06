# keycloak-idp-hashedId-mapper
A pluggable IdP mapper for keycloak. To be used in eosc installations 

###Installation instructions:

1. Compile the plugin jar i.e. 'mvn clean install' or just get a built one from the "actions" tab. 


Create the following folders:
$KEYCLOAK_BASE/modules/system/layers/keycloak/org/keycloak/keycloak-idp-hashedId-mapper
$KEYCLOAK_BASE/modules/system/layers/keycloak/org/keycloak/keycloak-idp-hashedId-mapper/main

and add into the folder "main" 
* the built jar keycloak-idp-hashedId-mapper/target/keycloak-idp-hashedId-mapper.jar
* the keycloak-idp-hashedId-mapper/module.xml from the source ([this](https://raw.githubusercontent.com/eosc-kc/keycloak-idp-hashedId-mapper/main/module.xml) one) base folder 

so you should end up with the following structure in
$KEYCLOAK_BASE/modules/system/layers/keycloak/org/keycloak/keycloak-idp-hashedId-mapper

```
keycloak-idp-hashedId-mapper
└── main
    ├── keycloak-idp-hashedId-mapper.jar
    └── module.xml
```

Following the above, we should also let wildfly server and keycloak to load this module as well. 
So, open file $KEYCLOAK_BASE/standalone/configuration/standalone.xml or $KEYCLOAK_BASE/standalone/configuration/standalone-ha.xml

Find the ```<subsystem xmlns="urn:jboss:domain:keycloak-server:1.1">``` node.

* Add the 
```<provider>module:org.keycloak.keycloak-idp-hashedId-mapper</provider>```
into the ```<providers>``` list


You should then be able to use the SAML IdentityProvider mapper **Hashed User ID Mapper**  as named in the UI droplist. 
