# keycloak-idp-hashedId-mapper
A pluggable IdP mapper for keycloak. To be used in eosc installations 

###Installation instructions:

1. Compile the plugin jar i.e. 'mvn clean install'
2. Copy the file into the **modules/system/layers/keycloak/org/keycloak/keycloak-idp-hashedId-mapper/main** folder in keycloak installation - create the intermediate **keycloak-idp-hashedId-mapper/main** folders.
3. Add the provided **module.xml** file in the same folder where you previously copied the jar
4. Add the entry ``` <module name="org.keycloak.keycloak-idp-hashedId-mapper" services="import"/> ``` in the ```<dependencies>``` section of the ``` modules/system/layers/keycloak/org/keycloak/keycloak-services/main/module.xml``` file

You should then be able to use the SAML IdentityProvider mapper **Hashed User ID Mapper**  as named in the UI droplist. 
