# Keycloak-laverca

This project is a keycloak extension which adds support for Kiuru MSSP MobileID authentication through (Laverca-rest project)[https://github.com/methics/laverca-rest].


## Requirements

- OpenJDK 17
- Maven


## Keycloak setup

Download and extract keycloak-22.0.3.zip from the Keycloak website.
After extracting this file, you should have a directory named keycloak-22.0.3.

* From a terminal, move to keycloak directory
* Enter the following command:

On linux, run:

`bin/kc.sh start-dev`

on Windows, run:

`bin/kc.bat start-dev`


### Create an admin user
Keycloak has no default admin user. You need to create an admin user before you can start Keycloak. By default the server runs on port 8080.

*  Open http://localhost:8080/
* Login with the username and password you created earlier

### Installing the extension

All extensions to be added need to be copied over to /providers directory inside the Keycloak folder. 
Remember to add dependencies in the same folder, for example laverca-rest-1.1.0.jar

(You can find laverca-rest project from our GitHub)[https://github.com/methics/laverca-rest]

### Validating extension installation

When starting Keycloak in development mode with bin/kc.sh start-dev, you can see if extension is being loaded:

```
Updating the configuration and installing your custom providers, if any. Please wait.
2023-10-02 11:45:49,365 WARN  [org.keycloak.services] (build-45) KC-SERVICES0047: oidc-lavercaprotocolmapper (fi.methics.keycloak.laverca.MobileidAccessTokenMapper) is implementing the internal SPI protocol-mapper. This SPI is internal and may change without notice
2023-10-02 11:45:49,387 WARN  [org.keycloak.services] (build-45) KC-SERVICES0047: mobileid-authentication (fi.methics.keycloak.laverca.MobileidAuthenticatorFactory) is implementing the internal SPI authenticator. This SPI is internal and may change without notice
```

You should also validate the extension by:

* navigating to (Keycloak admin console)[http://localhost:8080/admin/master/console/#/master/providers]
* Make sure you can find "mobileid-authentication" in the authenticator section.


### Enabling MobileID authentication

Before enabling mobileid authentication, you should have created a new realm.

To enable MobileID authentication as your browser flow, you should:

* Navigate to realm Authentication section
* Press "Create flow" button
* Insert flow name e.g. "mobileid authentication
* Set flow type as "Basic flow"
* Add an execution and select "Mobile ID authentication"
* Set requirement as "Enabled"
* Navigate to Authentication section of your Realm
* bind "mobileid-authentication" flow to "Browser flow" by pressing on the three dots at the end of the line

When signing in from your client, you should be asked for your MSISDN instead of username/password.

### Configuring the extension

You need to have a connection to Kiuru MSSP to be able to use MobileID authentication. To configure the extension:

* Login as admin to Keycloak admin UI 
* Navigate to your realm
* Navigate to mobileid authentication flow
* Press the settings icon
* Configure your Application Provider details
* Configure "Enabled subject attributes"

Enabled subject attributes are the values you expect to get from the Subject when you sign.

# Building

`mvn clean package`