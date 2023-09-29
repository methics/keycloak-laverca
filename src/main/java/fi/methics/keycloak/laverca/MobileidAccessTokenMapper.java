package fi.methics.keycloak.laverca;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.protocol.ProtocolMapperUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MobileidAccessTokenMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID = "oidc-lavercaprotocolmapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();


    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("claims");
        property.setLabel("Claims");
        property.setHelpText("Claims read from user attributes");
        property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        configProperties.add(property);
    }


    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "Mobileid Custom Claim Mapper";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Laverca mobileid custom claim mapper";
    }

    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel, KeycloakSession keycloakSession,
                                            UserSessionModel userSession, ClientSessionContext clientSessionCtx) {

        //TODO: Find out why this errors
        ProviderConfigProperty claims = configProperties.stream().filter(config->config.getName().equals("claims")).findFirst().orElse(null);

        // Get roles from user attributes
        List<String> msspRoles = userSession.getUser().getAttributes().get("mssp_roles");

        if (msspRoles != null) {
            String roles = String.join(", ", msspRoles);
            token.getOtherClaims().put("mssp_roles", roles);
        }

        setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        return token;
    }


    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel, KeycloakSession session, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        // When trying to configure these in dedicated scopes -> mapper details we get "Could not update mapping: 'unknown_error'"
        ProviderConfigProperty claims = configProperties.stream().filter(config->config.getName().equals("claims")).findFirst().orElse(null);

        // See what user attributes we saved
        String userAttributes = userSession.getUser().getAttributes().toString();
        System.out.println("(transformIDToken) userAttributes: " + userAttributes);

        //TODO: For now we have to hardcode these claim values since configs cant be saved in keycloak due to error
        String msisdn = userSession.getUser().getUsername();
        System.out.println("(transformIDToken): MSISDN: " + msisdn);

        // What should we put in claims?
        String givenName = userSession.getUser().getFirstAttribute("givenname");
        String surname   = userSession.getUser().getFirstAttribute("surname");
        String country   = userSession.getUser().getFirstAttribute("c");
        String email     = userSession.getUser().getFirstAttribute("email");

        if (msisdn != null)    token.setPhoneNumber(msisdn);
        if (givenName != null) token.setName(givenName);
        if (surname != null)   token.setFamilyName(surname);
        if (country != null)   token.setLocale(country);
        if (email != null)     token.setEmail(email);

        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    public static ProtocolMapperModel create(String name,
                                             boolean accessToken, boolean idToken, boolean userInfo) {
        ProtocolMapperModel mapper = new ProtocolMapperModel();
        mapper.setName(name);
        mapper.setProtocolMapper(PROVIDER_ID);
        mapper.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        Map<String, String> config = new HashMap<String, String>();
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN, "true");
        config.put(OIDCAttributeMapperHelper.INCLUDE_IN_ID_TOKEN, "true");
        mapper.setConfig(config);
        return mapper;
    }
}