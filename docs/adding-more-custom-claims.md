# Adding more custom claims


Adding other claims than which are available via Enabled subject attributes requires changes to the source code.

By modifying the code in MobileidAccessTokenMapper.java, we can add more custom claims to ID token and Access token. If the claims you need to be added can be gotten from MSSP given Subject, you can just add more Enabled subject attributes.

1. Make sure you Enabled subject attributes
2. Modify the code in MobileidAccessTokenMapper.java

for example:

```java
public IDToken transformIDToken(
                IDToken token,
                ProtocolMapperModel mappingModel,
                KeycloakSession session,
                UserSessionModel userSession,
                ClientSessionContext clientSessionCtx) 
{
     // existing code...
     
     String someAttribute = userSession.getUser().getFirstAttribute("someAttribute");
     if (someAttribute != null) token.getOtherClaims().put("someAttribute", "theValue");
     
     setClaim(token, mappingModel, userSession, session, clientSessionCtx);
     return token;
}
```