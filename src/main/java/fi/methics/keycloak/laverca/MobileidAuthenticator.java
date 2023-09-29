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
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.*;


public class MobileidAuthenticator implements Authenticator {

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
        System.out.println("ENABLED ATTRIBUTES: " + enabledAttributes);

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
            /*
            MSS_SignatureResp resp = client.authenticate(
                    msisdn,
                    dtbd,
                    SignatureProfile.of("http://alauda.mobi/digitalSignature"));
             */

            MSS_SignatureResp resp = client.sign(req);

            // Authenticated
            if (resp.isSuccessful()) {
                System.out.println("Successfully authenticated " + resp.getSubjectDN());
                System.out.println("cert: " + resp.getCertificate());

                // Check does this msisdn have a keycloak user already?
                KeycloakSession session = context.getSession();
                RealmModel realm = context.getRealm();
                UserModel existingUser = session.users().getUserByUsername(realm, msisdn);

                // Remove debug
                System.out.println("DEBUG: SUBJECT" + resp.getSubjectDN());


                if (existingUser == null) {
                    UserModel newUser = session.users().addUser(realm, msisdn);
                    newUser.setEnabled(true);

                    for (String attr : attrs) {
                        if (resp.getSubjectAttribute(attr) == null) {
                            System.out.println("Could not find " + attr + " in resp.getSubjectAttribute()");
                            continue;
                        }
                        newUser.setSingleAttribute(attr, resp.getSubjectAttribute(attr));
                    }
                    context.setUser(newUser);
                } else {

                    // Loop through enabled attributes configured in keycloak and add them to user attributes
                    // so we can use them in MobileidAccessTokenMapper
                    for (String attr : attrs) {
                        if (resp.getSubjectAttribute(attr) == null) {
                            System.out.println("Could not find " + attr + " in resp.getSubjectAttribute()");
                            continue;
                        }
                        System.out.println("found attribute: " + resp.getSubjectAttribute(attr));
                        existingUser.setSingleAttribute(attr, resp.getSubjectAttribute(attr));
                    }

                    // Get MSSP roles
                    for (ServiceResponses serviceResp : resp.ServiceResponses) {
                        if (serviceResp.Description.equals("http://www.methics.fi/KiuruMSSP/v5.0.0#role")) {
                            System.out.println(serviceResp.Roles);
                            // add roles to user attributes to be used in accessToken
                            existingUser.setAttribute("mssp_roles", serviceResp.Roles);
                        }
                    }

                    System.out.println("Found existing keycloak user for " + msisdn);
                    existingUser.setEnabled(true);
                    context.setUser(existingUser);
                    System.out.println("AUTHENTICATED USER: " + existingUser.getUsername());
                }

                context.success();
            }
        } catch (Exception e) {
            System.out.println("Failed to authenticate user" + e);
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

}
