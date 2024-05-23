# Adding Claims to JWT's

Keycloak-laverca has a custom access token mapper. To enable Keycloak JWT's to include custom claims built from the data MSSP responds with:


1. In your specified Realm, go to Clients
2. Select your Client
3. Navigate to Client Scopes
4. Click [clientname]-dedicated
5. Click "Configure a new mapper" button
6. Select "Mobileid Custom Claim Mapper"
7. Enter name and click Save button

Now keycloak-laverca extension will map all wanted and available subject attributes that it finds from Kiuru MSSP's response. The wanted claims are the same as configured Enabled Subject Attributes.
