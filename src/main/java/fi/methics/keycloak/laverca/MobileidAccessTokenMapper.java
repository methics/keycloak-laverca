package fi.methics.keycloak.laverca;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MobileidAccessTokenMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {
    public static final String PROVIDER_ID = "oidc-lavercaprotocolmapper";
    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

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
        UserModel user = userSession.getUser();
        Map<String, List<String>> attributes =  user.getAttributes();

        for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
            String attributeName = entry.getKey();

            // dont add mssp roles to ID token
            if (attributeName.equals("mssp_roles")) continue;

            List<String> attributeValues = entry.getValue();
            List<String> multipleValues = new ArrayList<>();

            for (String attributeValue : attributeValues) {
                if (attributeValue == null) continue;
                multipleValues.add(attributeValue);
            }

            String attributeString = String.join(",", multipleValues);
            token.getOtherClaims().put(attributeName, attributeString);
        }

        setClaim(token, mappingModel, userSession, session, clientSessionCtx);
        return token;
    }

    public static ProtocolMapperModel create(String name, boolean accessToken, boolean idToken, boolean userInfo) {
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