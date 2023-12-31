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

        // Get the configured allowed methods for getting MSISDN
        final String allowedMsisdnMethod = context.getAuthenticatorConfig().getConfig().get("allowed-msisdn-method");
        if (allowedMsisdnMethod == null) {
            logger.error("Administrator has not configured the acceptable method(s) to receive MSISDN");
            context.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        // Get the query params
        String query = context.getUriInfo().getRequestUri().getQuery();
        String[] params = query.split("&");

        // Get DTBD and MSISDN from the client, if they sent it.
        String dtbdValue = null;
        String msisdn = null;
        for (String param : params) {
            if (param.startsWith("dtbd=")) {
                dtbdValue = param.substring(5);
                context.getAuthenticationSession().setClientNote("dtbdFromUrl", dtbdValue);
            }
            if (param.startsWith(("msisdn="))) {
                msisdn = param.substring(7);
                context.getAuthenticationSession().setClientNote("msisdn", msisdn);
            }
        }

        if (dtbdValue == null) logger.warn("Client application did not send DTBD");
        if (msisdn == null)    logger.info("Client did not specify MSISDN");

        if (allowedMsisdnMethod.equals("URL")) {
            if (msisdn != null) {
                // Only URL is a valid way to receive MSISDN
                // MSISDN found in URL, proceed without displaying form
                action(context);
            } else {
                // No MSISDN in the URL
                logger.error("MSISDN only allowed to be received from URL, but request did not contain MSISDN");
                context.failure(AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
            }
            return;
        }

        if (allowedMsisdnMethod.equals("FORM")) {
            // MSISDN only allowed to be received from FORM
            Response response = context.form().createForm("mobileid-form.ftl");
            context.challenge(response);
            return;
        }

        if (allowedMsisdnMethod.equals("BOTH")) {
            if (msisdn == null) {
                // Both methods allowed, but request did not contain MSISDN, display form to get it
                Response response = context.form().createForm("mobileid-form.ftl");
                context.challenge(response);
            } else {
                // URL had MSISDN in it, call MSSP with it
                action(context);
            }
        }

    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Get dtbd from client note
        String dtbdValue = context.getAuthenticationSession().getClientNotes().get("dtbdFromUrl");

        if (dtbdValue == null) {
            logger.info("no dtbd value in params");
        }

        // Get AP configs from keycloak
        final Map<String, String> config = context.getAuthenticatorConfig().getConfig();
        String clientId = context.getAuthenticationSession().getClient().getClientId();
        String restUrl  = config.get("mssp-url");
        String apName   = config.get("ap-name");
        String apPwd    = config.get("ap-password");
        String enabledAttributes = config.get("enabled-subject-attributes");
        String signatureProfile  = config.get("signature-profile");
        String dtbd     = (dtbdValue != null) ? dtbdValue : config.get("data-to-be-displayed") + " " + clientId;

        // EnabledAttributes configured in keycloak
        List<String> attrs = Arrays.asList(enabledAttributes.split("##"));
        if (attrs.isEmpty()) logger.warn("Admin has not configured enabled subject attributes");

        String msisdn = context.getAuthenticationSession().getClientNotes().get("msisdn");
        if (msisdn == null) {
            // No MSISDN in url, get it from form
            MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
            msisdn = formData.getFirst("msisdn");
        }

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
        builder.withSignatureProfile(SignatureProfile.of(signatureProfile));

        MSS_SignatureReq req = builder.build();
        req.AdditionalServices.add(new AdditionalServices("http://www.methics.fi/KiuruMSSP/v5.0.0#role"));

        try {
            MSS_SignatureResp resp = client.sign(req);

            // Authenticated
            if (resp.isSuccessful()) {
                logger.info("Successfully authenticated with MobileID with msisdn " + msisdn);
                KeycloakSession session = context.getSession();
                RealmModel realm = context.getRealm();

                // Check if user exists in keycloak, if not then create it
                UserModel existingUser = session.users().getUserByUsername(realm, msisdn);
                UserModel user = (existingUser == null) ? this.createUser(context, msisdn, resp) : existingUser;

                // User returned null because MSSP user did not have "keycloak_admin" role
                if (user == null) {
                    context.failure(AuthenticationFlowError.ACCESS_DENIED);
                    return;
                }

                // Set attributes and roles for current user
                this.setAttributes(user, attrs, resp);
                context.setUser(user);
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
     * @param user UserModel
     * @param attributes List<String>
     * @param resp MSS_SignatureResp
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
     * Creates user in keycloak, set roles from MSS_SignatureResp and gives access to keycloak admin panel based on MSSP roles.
     * @param context AuthencationContextFlow
     * @param msisdn String
     * @param resp MSS_SignatureResp
     * @return UserModel
     */
    private UserModel createUser(AuthenticationFlowContext context, String msisdn, MSS_SignatureResp resp) {
        logger.info("No user found for msisdn " + msisdn + ", creating user");
        KeycloakSession session = this.session;
        UserModel newUser       = session.users().addUser(context.getRealm(), msisdn);
        RealmModel realm        = context.getRealm();
        newUser.setEnabled(true);

        // Check if MSS_SignatureResp had roles in it, set to user attributes
        List<String> roles = null;
        for (ServiceResponses serviceResp : resp.ServiceResponses) {
            if (serviceResp.Description.equals("http://www.methics.fi/KiuruMSSP/v5.0.0#role")) {
                logger.info("Found MSSP roles " + serviceResp.Roles + " for user: " + msisdn);
                newUser.setAttribute("mssp_roles", serviceResp.Roles);
                roles = serviceResp.Roles;
            }
        }

        if (roles == null) return newUser;

        /*
            To access keycloak admin ui, the user must have "admin" role given.
            To allow admin role to be given to user, "keycloak_admin" role should come from MSSP.
            This makes sure that no ordinary mobile user can gain illicit access
         */
        if (realm.getName().equals("master")) {
            if (!roles.contains("keycloak_admin")) {
                logger.warn("Can't give Keycloak ADMIN access to " + newUser.getUsername() +
                            " because mobile user did not have 'keycloak_admin' role.");
                // Return null so no extra users are created
                return null;
            }

            RoleModel adminRole = realm.getRole("admin");
            if (adminRole != null) {
                logger.info("Adding admin role for " + msisdn +" to give access to admin UI");
                newUser.grantRole(adminRole);
            }

        }

        return newUser;
    }

}
