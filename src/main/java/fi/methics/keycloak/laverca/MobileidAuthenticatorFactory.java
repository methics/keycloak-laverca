package fi.methics.keycloak.laverca;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.Config;


import java.util.ArrayList;
import java.util.List;

public class MobileidAuthenticatorFactory implements AuthenticatorFactory {

    private static final String PROVIDER_ID = "mobileid-authentication";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    static {
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("mssp-url");
            property.setLabel("MSSP url");
            property.setType(ProviderConfigProperty.STRING_TYPE);
            property.setHelpText("MSSP URL");
            configProperties.add(property);
        }
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("ap-name");
            property.setLabel("Application provider name");
            property.setType(ProviderConfigProperty.STRING_TYPE);
            property.setHelpText("Application provider name");
            configProperties.add(property);
        }
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("ap-password");
            property.setLabel("Application provider REST password");
            property.setType(ProviderConfigProperty.STRING_TYPE);
            property.setHelpText("Application provider REST password");
            configProperties.add(property);
        }
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("data-to-be-displayed");
            property.setLabel("Authentication message (DTBD)");
            property.setType(ProviderConfigProperty.STRING_TYPE);
            property.setHelpText("Authentication message (DTBD)");
            configProperties.add(property);
        }
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("signature-profile");
            property.setLabel("Signature Profile");
            property.setType(ProviderConfigProperty.STRING_TYPE);
            property.setHelpText("Signature profile to be used");
            configProperties.add(property);
        }
        {
            ProviderConfigProperty property = new ProviderConfigProperty();
            property.setName("enabled-subject-attributes");
            property.setLabel("Enabled Subject Attributes");
            property.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
            property.setHelpText("Keycloak attributes read from user's authentication certificate subject");
            configProperties.add(property);
        }

    }

    @Override
    public String getDisplayType() {
        // Displayed in keycloak UI
        return "Mobile ID authentication";
    }

    @Override
    public String getReferenceCategory() {
        // Displayed in keycloak UI
        return "Mobile ID";
    }

    @Override
    public boolean isConfigurable() {
        // TODO: What can be configured?
        return true;
    }

    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "MobileID authenticator. ";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }


    @Override
    public Authenticator create(KeycloakSession session) {
        return new MobileidAuthenticator(session);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public void close() {
        //TODO: Anything we need to do when the server closes?
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
    }
}
