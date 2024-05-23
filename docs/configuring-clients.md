# Configuring Clients

Requiring different clients to have different accepted methods of receiving MSISDN is possible.

If you need different clients to have different methods of receiving MSISDN, you need to make multiple authentication flows.

During creation of authentication flows, available MSISDN methods are configured in same place as other keycloak-laverca related configuration.

Below you can see sample named authentication methods and sample settings regarding allowed methods of getting MSISDN.


## Client example
| Client  | Wanted Behavior                                                    | Required Allowed Method | Flow Override  |
|---------|--------------------------------------------------------------------|-------------------------|----------------|
| Client1 | MSISDN must be sent in URL, no form can never be displayed to user | URL                     | mid-authn-url  |
| Client2 | MSISDN can't be received from URL. Form must be displayed          | FORM                    | mid-authn-form |
| Client3 | Both methods are accepted                                          | BOTH                    | mid-authn-both |

## Setting Specific Flow Overrides
Different clients may have different accepted methods and can be configured under 

1. Clients
2. Client name
3. Advanced tab
4. Authenticatio nflow overrides (in the very end of the page)


# Relying party client requirements

There are two things to take into consideration when authenticating with MobileID through Keycloak:

1. Data to be displayed (DTBD)
2. Client requirement of how Keycloak expects to receive MSISDN

### Data to be displayed (DTBD)

Data to be displayed is the message that the user will see on their end of the authentication flow, before entering PIN. If this value is not specified by the relying party client, a default will be used. 

### MSISDN requirement 

Different accepted methods of receiving URL create different requirements for the relying party.

Requirements for client admins / developers:

| Method | Requirement                | Effects                                                                                 |
|--------|----------------------------|-----------------------------------------------------------------------------------------|
| URL    | MSISDN must be sent in URL | If MSISDN not sent in URL, request will result in failure                               |
| FORM   | None                       | Form will always be displayed, even if MSISDN is sent in URL                            |
| BOTH   | None                       | If MSISDN is not received from URL, form will be presented for the user to enter MSISDN |

See sample code example in Adding Keycloak authentication to Relying Party client.