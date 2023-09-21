package fi.methics.keycloak.laverca;


import fi.methics.laverca.rest.MssClient;
import fi.methics.laverca.rest.json.MSS_SignatureResp;
import fi.methics.laverca.rest.util.SignatureProfile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

import java.util.Map;


public class MobileidAuthenticator implements Authenticator {

    private final KeycloakSession session;

    public MobileidAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        System.out.println("Are we seeing a form?");
        MultivaluedMap<String, String> formParams = context.getHttpRequest().getDecodedFormParameters();
        System.out.println(formParams);

        Response response = context.form().createForm("mobileid-form.ftl");
        context.challenge(response);

    }

    @Override
    public void action(AuthenticationFlowContext context) {

        final Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        System.out.println("CONFIG     " + config);
        String restUrl = config.get("mssp-url");
        String apName  = config.get("ap-name");
        String apPwd   = config.get("ap-password");
        String dtbd    = config.get("data-to-be-displayed");

        // Get the MSISDN from form
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String msisdn = formData.getFirst("msisdn");
        //String msisdn = "35847001001";

        MssClient client = new MssClient.Builder()
                .withRestUrl(restUrl)
                .withPassword(apName, apPwd)
                .build();


        try {
            MSS_SignatureResp resp = client.authenticate(
                    msisdn,
                    dtbd,
                    SignatureProfile.of("http://alauda.mobi/digitalSignature"));
            // Authenticated
            if (resp.isSuccessful()) {
                System.out.println("Successfully authenticated " + resp.getSubjectDN());
                System.out.println("cert: " + resp.getCertificate());

                // Check does this msisdn have a keycloak user already?
                KeycloakSession session = context.getSession();
                RealmModel realm = context.getRealm();
                UserModel existingUser = session.users().getUserByUsername(realm, msisdn);

                if (existingUser == null) {
                    System.out.println("User for " + msisdn + " does not have user, lets create it");
                    // We need to create keycloak user for this MSISDN, so we can issue tokens
                    UserModel newUser = session.users().addUser(realm, msisdn);

                    // Set account enabled and email verified to not face "Network error"...
                    newUser.setEmail("something@methics.fi");
                    newUser.setEnabled(true);
                    newUser.setEmailVerified(true);
                    RoleModel adminRole = realm.getRole("admin");
                    if (adminRole != null) {
                        newUser.grantRole(adminRole);
                    }
                    context.setUser(newUser);
                } else {
                    System.out.println("Found existing keycloak user for " + msisdn);
                    // Set account enabled and email verified to not face "Network error"...
                    existingUser.setEnabled(true);
                    existingUser.setEmail("abc@methics.fi");
                    existingUser.setEmailVerified(true);
                    //System.out.println(existingUser.credentialManager().isValid());
                    RoleModel adminRole = realm.getRole("admin");

                    // Don't try to grant admin role if it doesnt exist
                    if (adminRole != null) {
                        existingUser.grantRole(adminRole);
                    }
                    context.setUser(existingUser);
                    System.out.println("AUTHENTICATED USER: " + existingUser.getUsername());
                }

                context.success();
            }
        } catch (Exception e) {
            System.out.println("Failed to authenticate user" + e);
            context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
        //context.success();

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void close() {
    }

}
