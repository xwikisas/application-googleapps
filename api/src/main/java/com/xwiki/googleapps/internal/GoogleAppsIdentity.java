/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.googleapps.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.PeopleServiceScopes;
import com.google.api.services.people.v1.model.EmailAddress;
import com.google.api.services.people.v1.model.Person;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.XWikiRequest;
import com.xwiki.googleapps.GoogleAppsException;

/**
 * Set of objects to recognize and read the identity of the user.
 * @since 3.0
 * @version $Id$
 */
@Component(roles = GoogleAppsIdentity.class)
@Singleton
public class GoogleAppsIdentity implements GoogleAppsConstants
{
    /**
     * A map of hash to full redirects.
     */
    private final Map<String, String> storedStates = new HashMap<>();

    @Inject
    private Logger log;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Provider<GoogleAppsXWikiObjects> gaXwikiObjects;

    @Inject
    private Provider<CookieAuthenticationPersistence> cookiePersistence;


    private JacksonFactory jacksonFactory;

    private NetHttpTransport httpTransport;

    private FileDataStoreFactory dsFactory;



    private void initIfNeedBe() {
        if (this.jacksonFactory==null) {
            try {
                this.jacksonFactory = JacksonFactory.getDefaultInstance();
                this.httpTransport = GoogleNetHttpTransport.newTrustedTransport();
                this.dsFactory =  new FileDataStoreFactory(gaXwikiObjects.get().getPermanentDir());
            } catch (Exception e) {
                e.printStackTrace();
                throw new GoogleAppsException("Trouble at constructing GoogleAppsIdentity", e);
            }
        }
    }


    String updateUser()
    {
        initIfNeedBe();
        try {
            if (!gaXwikiObjects.get().isActive()) {
                return FAILEDLOGIN;
            }
            log.debug("Updating user...");
            Credential credential = authorize(true);

            Person gUser = null;
            if (credential != null) {
                PeopleService pservice = new PeopleService.Builder(httpTransport,
                        jacksonFactory, credential)
                        .setApplicationName(gaXwikiObjects.get().getConfigAppName())
                        .build();
                gUser = pservice.people().get("people/me").setPersonFields("emailAddresses,names,photos").execute();
                // GOOGLEAPPS: User: [displayName:..., emails:[[type:account, value:...]], etag:"...",
                // id:...., image:[isDefault:false, url:https://...], kind:plus#person, language:en,
                // name:[familyName:..., givenName:...]]
            }
            log.debug("user on google: " + gUser);
            if (gUser == null) {
                return NOUSER;
            }

            String xwikiUser;
            List<String> emails = new ArrayList<>();
            // grab emailaddresses
            if (gUser.getEmailAddresses() != null) {
                for (EmailAddress address : gUser.getEmailAddresses()) {
                    emails.add(address.getValue());
                }
            }
            String email = checkDomain(emails);
            if (email == null) {
                return FAILEDLOGIN;
            }

            String firstName = null;
            String lastName = null;
            if (gUser.getNames() != null) {
                firstName = gUser.getNames().get(0).getGivenName();
                lastName = gUser.getNames().get(0).getFamilyName();
            }

            String googleUserId = (String) gUser.get("resourceName");

            String photoUrl = extractPhotoUrl(gUser);
            xwikiUser = gaXwikiObjects.get().updateXWikiUser(googleUserId, emails, email,
                    firstName, lastName, photoUrl);

            // we need to restore the credentials as the user will now be logged-in
            storeCredentials(xwikiUser, credential);

            // store the validated xwiki user for the authentication module
            // TODO: discuss: Is this not a security risk?
            contextProvider.get().getRequest().getSession().setAttribute("googleappslogin", xwikiUser);
            return "ok";
        } catch (Exception e) {
            log.warn("Problem at updateUser", e);
            return NOUSER;
        }
    }

    private String checkDomain(List<String> emails)
    {
        String email = null;
        String domain = gaXwikiObjects.get().getConfigDomain();
        if (domain != null && domain.length() > 0) {
            domain = domain.trim();
            for (String address : emails) {
                if (address.endsWith(domain)) {
                    email = address;
                    break;
                }
            }
            if (email == null) {
                String userId = getCurrentXWikiUserName();
                getCredentialStore().remove(userId);
                log.debug("Wrong domain: Removed credentials for userid " + userId);
                return null;
            }
        }
        return emails.isEmpty() ? null : emails.get(0);
    }

    private String extractPhotoUrl(Person gUser)
    {
        if (gaXwikiObjects.get().getConfigScopeUseAvatar()
                && gUser.getPhotos() != null
                && gUser.getPhotos().size() > 0
                && gUser.getPhotos().get(0).getUrl() != null)
        {
            String photoUrl = gUser.getPhotos().get(0).getUrl();
            log.debug("Avatar " + photoUrl);
            return photoUrl;
        }
        return null;
    }

    private String getOAuthUrl()
    {
        try {
            XWikiContext context = contextProvider.get();

            DocumentReference loginPage = new DocumentReference(context.getWikiId(),
                    XWIKISPACE, XWIKILOGIN);
            String u = context.getWiki().getDocument(loginPage, context).getExternalURL("login",
                    "googleLogin=oauthReturn", context);
            return u;
        } catch (Exception e) {
            throw new GoogleAppsException("Trouble at getting OAuth URL", e);
        }
    }

    private String getCurrentXWikiUserName()
    {
        initIfNeedBe();
        DocumentReference userDoc = contextProvider.get().getUserReference();
        String uName = userDoc == null ? XWIKIGUEST : userDoc.getName();
        if (XWIKIGUEST.equals(uName)) {
            uName = uName + "-" + contextProvider.get().getRequest().getSession().hashCode();
        }
        return uName;
    }

    /**
     * Build flow and trigger user authorization request.
     *
     * @return the configured flow
     * @throws GoogleAppsException in case something can't be built
     */
    private GoogleAuthorizationCodeFlow getFlow()
    {
        initIfNeedBe();
        try {
            // create scopes from config
            List<String> gScopes = new ArrayList<>();
            gScopes.add(PeopleServiceScopes.USERINFO_EMAIL);
            gScopes.add(PeopleServiceScopes.USERINFO_PROFILE);
            if (gaXwikiObjects.get().doesConfigScopeUseDrive()) {
                gScopes.add(DriveScopes.DRIVE);
            }

            // create flow
            return new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport,
                    jacksonFactory, gaXwikiObjects.get().getConfigClientId(),
                    gaXwikiObjects.get().getConfigClientSecret(), gScopes)
                    .setDataStoreFactory(dsFactory)
                    .setAccessType("online").setApprovalPrompt(AUTOAPPROVAL)
                    .setClientId(gaXwikiObjects.get().getConfigClientId())
                    .build();
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException("Issue at building Google Authorization Flow.", e);
        }
    }

    /**
     * Exchange an authorization code for OAuth 2.0 credentials.
     *
     * @param authorizationCode Authorization code to exchange for OAuth 2.0 credentials.
     * @return OAuth 2.0 credentials.
     */
    private Credential exchangeCode(String authorizationCode)
    {
        initIfNeedBe();
        try {
            GoogleAuthorizationCodeFlow flow = getFlow();
            GoogleTokenResponse tokenResponse = flow
                    .newTokenRequest(authorizationCode)
                    .setRedirectUri(getOAuthUrl())
                    .execute();
            log.debug("Token: " + tokenResponse);
            return flow.createAndStoreCredential(tokenResponse, getCurrentXWikiUserName());
        } catch (Exception ex) {
            throw new GoogleAppsException("Trouble at exchanging authorization code", ex);
        }
    }

    private Map<String, Credential> getCredentialStore()
    {
        initIfNeedBe();
        final String key = "GoogleAppsCredentialStore";
        HttpSession session = contextProvider.get().getRequest().getSession(true);
        Map<String, Credential> store = (Map<String, Credential>) (session.getAttribute(key));
        if (store == null) {
            store = new HashMap<>();
            session.setAttribute(key, store);
        }
        return store;
    }

    private void storeCredentials(String userId, Credential credentials)
    {
        try {
            if (userId.contains(XWIKIGUEST)) {
                if (gaXwikiObjects.get().doesUseCookies()) {
                    cookiePersistence.get().setUserId(userId);
                }
            }
            log.debug("Storing credentials for user " + userId + " (" + credentials + ").");
            getCredentialStore().put(userId, credentials);
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException("Issue at storing credential.", e);
        }
    }

    private Credential getStoredCredentials(String userId)
    {
        if (userId == null) {
            return null;
        }
        log.debug("Getting credentials for user " + userId);
        return getCredentialStore().get(userId);
    }

    /**
     * Retrieve credentials using the provided authorization code.
     * <p>
     * This function exchanges the authorization code for an access token and queries the UserInfo API to retrieve the
     * user's e-mail address. If a refresh token has been retrieved along with an access token, it is stored in the
     * application database using the user's e-mail address as key. If no refresh token has been retrieved, the function
     * checks in the application database for one and returns it if found or throws a NoRefreshTokenException with the
     * authorization URL to redirect the user to.
     *
     * @param authorizationCode Authorization code to use to retrieve an access token.
     * @return OAuth 2.0 credentials instance containing an access and refresh token.
     * @throws GoogleAppsException Unable to load client_secret.json.
     */
    private Credential retrieveCredentials(String authorizationCode, boolean redirect)
    {
        try {
            Credential credentials;
            String user = getCurrentXWikiUserName();

            if (authorizationCode != null && authorizationCode.length() > 0) {
                log.debug("Trying to get credentials from authorization code: " + authorizationCode);
                credentials = exchangeCode(authorizationCode);
                if (credentials != null) {
                    if (credentials.getRefreshToken() != null) {
                        log.debug("Refresh token has been created.");
                    } else {
                        log.debug("Failure to create refresh token");
                    }
                    storeCredentials(user, credentials);
                    return credentials;
                }
            }

            log.debug("No credentials found. Checking stored credentials for user " + user);
            credentials = getStoredCredentials(user);
            if (credentials != null) {
                log.debug("Retrieved stored credentials");
                return credentials;
            }
            log.debug("Could not find stored credentials");

            log.debug("No credentials retrieved.");
            // No refresh token has been retrieved.
            if (redirect) {
                log.debug("Redirecting to authorization URL.");
                contextProvider.get().getResponse().sendRedirect(getAuthorizationURL());
            }
            return null;
        } catch (Exception e) {
            throw new GoogleAppsException("Trouble at retrieving credentials", e);
        }
    }

    private String getAuthorizationURL()
    {
        try {
            String state = "";
            XWikiContext context = contextProvider.get();
            XWikiRequest request = context.getRequest();
            DocumentReference ref = context.getDoc().getDocumentReference();
            if (!(XWIKILOGIN.equals(ref.getName()) && XWIKISPACE.equals(ref.getLastSpaceReference().getName()))) {

                String finalRedirect = context.getDoc().getURL(VIEWACTION, request.getQueryString(), context);
                state = Integer.toHexString(finalRedirect.hashCode());
                storedStates.put(state, finalRedirect);
            }

            GoogleAuthorizationCodeRequestUrl urlBuilder = getFlow()
                    .newAuthorizationUrl()
                    .setRedirectUri(getOAuthUrl())
                    .setState(state).setClientId(gaXwikiObjects.get().getConfigClientId())
                    .setAccessType("offline").setApprovalPrompt(AUTOAPPROVAL);
            // Add user email to filter account if the user is logged with multiple account
            if (gaXwikiObjects.get().doesUseCookies()) {
                String userId = cookiePersistence.get().getUserId();
                if (userId != null) {
                    String userEmail = gaXwikiObjects.get().getUserEmail(userId);
                    if (userEmail != null) {
                        urlBuilder = urlBuilder.set("login_hint", userEmail);
                    }
                }
            }
            String authurl = urlBuilder.build();
            log.debug("google authentication url : " + authurl);
            return authurl;
        } catch (Exception ex) {
            throw new GoogleAppsException("trouble at getAuthorizationURL", ex);
        }
    }

    /**
     * Inspects the stored information to see if an authorization or a redirect needs to be pronounced.
     *
     * @param redirect If a redirect can be done
     * @return found credential
     * @since 3.0
     */
    public Credential authorize(boolean redirect)
    {
        initIfNeedBe();
        try {
            log.debug("In authorize");
            // TODO: useless? GoogleAuthorizationCodeFlow flow =
            getFlow();
            XWikiContext context = contextProvider.get();
            XWikiRequest request = context.getRequest();
            String state = request.getParameter("code");
            Credential creds = retrieveCredentials(state, redirect);
            log.debug("Got credentials: " + creds);
            if (state != null && state.length() > 0) {
                String url = storedStates.get(state);
                if (url != null) {
                    log.debug("Redirecting to final destination after authorization: " + url);
                    context.getResponse().sendRedirect(url);
                }
            }
            return creds;
        } catch (Exception e) {
            log.warn("Trouble in authorize", e);
            throw new GoogleAppsException(e);
        }
    }
}
