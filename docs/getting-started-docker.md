# Getting started (Docker)

To start the development server using docker, you are required to have docker installed.
Start the development server with docker, run:

`docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:22.0.3 start-dev`

This allows you to simply test the default Keycloak installation. You can login to Keycloak admin UI with the credentials provided in the run command. http://localhost:8080/admin/master/console


## Adding extensions to docker container
As docker needs to have the .jar files located in /opt/keycloak/providers/, you should mount them through docker volume:

Save your .jar files in some location. /my_jars is used in this example

1. mkdir /my_jars/ <-- Use any location on your computer
2. cp keycloak-laverca-1.0.0.jar /my_jars/
3. cp laverca-rest-1.1.0.jar /my/jars/
4. Mount the directory while running the container:

`docker run -p 8080:8080 -v /my_jars:/opt/keycloak/providers -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:22.0.3 start-dev`

## Adding keycloak.conf to docker container
Use same flow as with adding the extensions. You can mount another location with a secondary -v flag.