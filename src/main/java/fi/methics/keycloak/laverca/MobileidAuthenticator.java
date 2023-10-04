package fi.methics.keycloak.laverca;


import fi.methics.laverca.rest.MssClient;
import fi.methics.laverca.rest.json.*;
import fi.methics.laverca.rest.util.DTBS;
import fi.methics.laverca.rest.util.MSS_SignatureReqBuilder;
import fi.methics.laverca.rest.util.SignatureProfile;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import java.util.*;
import org.jboss.logging.Logger;

public class MobileidAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(MobileidAuthenticator.class);
    private final KeycloakSession session;

    public MobileidAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String query = context.getUriInfo().getRequestUri().getQuery();
        String[] params = query.split("&");

        String dtbdValue = null;
        for (String param : params) {
            if (param.startsWith("dtbd=")) {
                dtbdValue = param.substring(5);
                context.getAuthenticationSession().setClientNote("dtbdFromUrl", dtbdValue);
                break;
            }
        }

        if (dtbdValue == null) logger.warn("Client application did not send DTBD");

        Response response = context.form().createForm("mobileid-form.ftl");
        context.challenge(response);
    }

    @Override
    public void action(AuthenticationFlowContext context) {

        // Get dtbd from client note
        String dtbdValue = context.getAuthenticationSession().getClientNotes().get("dtbdFromUrl");

        // Get AP configs from keycloak
        final Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        String restUrl  = config.get("mssp-url");
        String apName   = config.get("ap-name");
        String apPwd    = config.get("ap-password");
        String enabledAttributes = config.get("enabled-subject-attributes");
        String dtbd     = (dtbdValue != null) ? dtbdValue : config.get("data-to-be-displayed") + " " + clientId;

        // EnabledAttributes configured in keycloak
        List<String> attrs = Arrays.asList(enabledAttributes.split("##"));
        if (attrs.isEmpty()) logger.warn("Admin has not configured enabled subject attributes");

        // Get the MSISDN from form
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String msisdn = formData.getFirst("msisdn");

        MssClient client = new MssClient.Builder()
                .withRestUrl(restUrl)
                .withPassword(apName, apPwd)
                .build();

        final DTBS dtbs = new DTBS(dtbd);

        MSS_SignatureReqBuilder builder = new MSS_SignatureReqBuilder();
        builder.withDtbd(dtbd);
        builder.withDtbs(dtbs);
        builder.withMssFormat(MssClient.FORMAT_CMS);
        builder.withMsisdn(msisdn);
        builder.withSignatureProfile(SignatureProfile.of("http://alauda.mobi/digitalSignature"));

        MSS_SignatureReq req = builder.build();
        req.AdditionalServices.add(new AdditionalServices("http://www.methics.fi/KiuruMSSP/v5.0.0#role"));

        try {
            MSS_SignatureResp resp = client.sign(req);

            // Authenticated
            if (resp.isSuccessful()) {
                logger.info("Successfully authenticated with MobileID");
                // Check does this msisdn have a keycloak user already?
                KeycloakSession session = context.getSession();
                RealmModel realm = context.getRealm();
                UserModel existingUser = session.users().getUserByUsername(realm, msisdn);

                if (existingUser == null) {
                    logger.info("No existing user found for " + msisdn + ", lets create one");
                    UserModel newUser = session.users().addUser(realm, msisdn);
                    newUser.setEnabled(true);
                    this.setAttributes(newUser, attrs, resp);
                    this.setMsspRoles(newUser, resp);
                    context.setUser(newUser);
                } else {
                    this.setAttributes(existingUser, attrs, resp);
                    this.setMsspRoles(existingUser, resp);
                    existingUser.setEnabled(true);
                    context.setUser(existingUser);
                }

                context.success();
            }
        } catch (Exception e) {
            logger.error("Failed to authenticate user: " + msisdn + " " + e);
            context.failure(AuthenticationFlowError.GENERIC_AUTHENTICATION_ERROR);
        }

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

    /**
     * Sets enabled subject attributes for the user. These are the expected values to be saved from subject.
     * @param user
     * @param attributes
     * @param resp
     */
    private void setAttributes(UserModel user, List<String> attributes, MSS_SignatureResp resp) {
        logger.info("Setting attributes for " + user.getUsername());
        for (String attr : attributes) {
            if (resp.getSubjectAttribute(attr) == null) {
                continue;
            }
            user.setSingleAttribute(attr, resp.getSubjectAttribute(attr));
        }
    }

    /**
     * Sets MSSP roles to users attributes, so they can be accessed later.
     * @param user
     * @param resp
     */
    private void setMsspRoles(UserModel user, MSS_SignatureResp resp) {
        for (ServiceResponses serviceResp : resp.ServiceResponses) {
            if (serviceResp.Description.equals("http://www.methics.fi/KiuruMSSP/v5.0.0#role")) {
                logger.info("Found MSSP roles: " + serviceResp.Roles);
                user.setAttribute("mssp_roles", serviceResp.Roles);
            }
        }
    }

}
