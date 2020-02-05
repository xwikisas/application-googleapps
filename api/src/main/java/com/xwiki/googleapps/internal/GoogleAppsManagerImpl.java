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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.query.Query;
import org.xwiki.query.QueryException;
import org.xwiki.query.QueryManager;
import org.xwiki.stability.Unstable;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.InputStreamContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.PeopleServiceScopes;
import com.google.api.services.people.v1.model.EmailAddress;
import com.google.api.services.people.v1.model.Person;
import com.google.gdata.client.docs.DocsService;
import com.google.gdata.data.MediaContent;
import com.google.gdata.data.media.MediaSource;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.web.XWikiRequest;
import com.xpn.xwiki.web.XWikiResponse;
import com.xwiki.googleapps.DriveDocMetadata;
import com.xwiki.googleapps.GoogleAppsException;
import com.xwiki.googleapps.GoogleAppsManager;

/**
 * Set of methods accessible to the scripts using the GoogleApps functions.
 *
 * @version $Id$
 * @since 3.0
 */
@Component
@Singleton
public class GoogleAppsManagerImpl
        implements GoogleAppsManager, Initializable, Disposable
{

    private static final String AVATAR = "avatar";

    private static final String SPACENAME = "GoogleApps";

    private static final String VIEWACTION = "view";

    private static final String WIKINAME = "xwiki";

    private static final String XWIKISPACE = "XWiki";

    private static final String XWIKIGUEST = "XWikiGuest";

    private static final String AUTOAPPROVAL = "auto";

    private static final String EMAIL = "email";

    private static final String PASSWORD = "password";

    private static final String FIRSTNAME = "first_name";

    private static final String LASTNAME = "last_name";

    private static final String OAUTH = "OAuth";

    private static final String FAILEDLOGIN = "failed login";

    private static final String NOUSER = "no user";

    private static final String USER = "user";

    private static final String GOOGLEUSERATT = "googleUser";

    private static final String ID = "id";

    private static final String FILENAME = "fileName";

    private static final String VERSION = "version";

    private static final String URL = "url";

    private static final String EXPORTLINK = "exportLink";

    private static final String EDITLINK = "editLink";

    private static final String EMBEDLINK = "embedLink";

    private static final String UPDATECOMMENT = "Updated Google Apps Document metadata";

    private static final String EXPORTFORMATEQ = "exportFormat=";

    @Inject
    private Provider<XWikiContext> xwikiContextProvider;

    @Inject
    private QueryManager queryManager;

    @Inject
    private Environment environment;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> documentResolver;

    @Inject
    @Named("user")
    private DocumentReferenceResolver<String> userResolver;

    @Inject
    private Logger log;

    @Inject
    private ComponentManager componentManager;

    private GoogleAppsAuthServiceImpl authService;

    private DocumentReference configDocRef;

    private ObjectReference configObjRef;

    /**
     * A map of hash to full redirects.
     */
    private Map<String, String> storedStates = new HashMap<>();

    private FileDataStoreFactory dsFactory;

    private JacksonFactory jacksonFactory;

    private NetHttpTransport httpTransport;

    private CloseableHttpClient httpclient = HttpClients.createDefault();

    private Boolean configActiveFlag;

    private Boolean useCookies;

    private Boolean skipLoginPage;

    private Boolean authWithCookies;

    private String configAppName;

    private String configClientId;

    private String configClientSecret;

    private String configDomain;

    private Boolean configScopeUseAvatar;

    private Boolean configScopeUseDrive;

    private Integer configCookiesTTL;

    private DocumentReference gauthClassRef;

    @Override
    public void initialize() throws InitializationException
    {
        log.info("GoogleAppsScriptService initializing.");
        XWikiContext context = xwikiContextProvider.get();
        XWiki xwiki = context.getWiki();

        readConfigDoc(context);

        if (xwiki != null) {
            log.info("Initting authService.");
            // We do not verify with the context if the plugin is active and if the license is active
            // this will be done by the GoogleAppsAuthService and UI pages later on, when it is called within a request
            try {
                authService = componentManager.getInstance(GoogleAppsAuthService.class);
                xwiki.setAuthService(authService);
                log.info("Succeeded initting authService,");
            } catch (ComponentLookupException e) {
                log.info("Failed initting authService", e);
            }
        }
        if (authService == null) {
            log.info("Not yet initting authService.");
        }

        try {
            jacksonFactory = JacksonFactory.getDefaultInstance();
            httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        } catch (Exception e) {
            e.printStackTrace();
            throw new InitializationException("Trouble at initializing", e);
        }
    }

    private BaseObject getConfigDoc(XWikiContext context) throws XWikiException
    {
        configDocRef = getConfigDocRef();
        XWikiDocument doc = context.getWiki().getDocument(configObjRef, context);
        BaseObject result = doc.getXObject(configObjRef, false, context);
        if (result == null) {
            log.warn("Can't access Config document.");
        }
        return result;
    }

    /**
     * Evaluates weather the application is active and licensed by looking at the stored documents. Within a request,
     * this method should always be the first to be called so that the config-object is read and other properties are
     * cached if need be. The context is extracted from the thead-local.
     *
     * @return True if documents were readable, and the is licensed and active; false otherwise.
     * @since 3.0
     */
    @Unstable
    public boolean isActive()
    {
        return isActive(xwikiContextProvider.get());
    }

    /**
     * Evaluates weather the application is active and licensed by looking at the stored documents. Within a request,
     * this method should always be the first to be called so that the config-object is read and other properties are
     * cached if need be.
     *
     * @param context The context (a page request).
     * @return True if documents were readable, and the is licensed and active; false otherwise.
     * @since 3.0
     */
    @Unstable
    boolean isActive(XWikiContext context)
    {
        log.info("Is active " + this.toString() + " with configClient non-null? " + (configClientId != null));
        if (configActiveFlag == null || configClientId == null || configClientId.length() == 0) {
            readConfigDoc(context);
        }
        if (authService == null) {
            try {
                initialize();
            } catch (InitializationException e) {
                e.printStackTrace();
            }
        }
        if (configActiveFlag != null) {
            return configActiveFlag;
        }
        return false;
    }

    /**
     * @return true if the app is configured to use cookies to store the association to the Google user.
     * @since 3.0
     */
    @Unstable
    public boolean useCookies()
    {
        return useCookies;
    }

    /**
     * @return true if the app is configured to simply use the cookie and thus recognize the user based on cookie
     * @since 3.0
     */
    @Unstable
    public boolean skipLoginPage()
    {
        return skipLoginPage;
    }

    /**
     * @return true if the app is configured to use cookies to store the association to the Google user
     * @since 3.0
     */
    @Unstable
    public boolean authWithCookies()
    {
        return authWithCookies;
    }

    /**
     * @return how long (in seconds) the cookies should be valid
     * @since 3.0
     */
    @Unstable
    public int getConfigCookiesTTL()
    {
        return configCookiesTTL;
    }

    void readConfigDoc(XWikiContext contextp)
    {
        XWikiContext context = contextp;
        if (context == null) {
            context = xwikiContextProvider.get();
        }

        try {
            log.warn("Attempting to fetch Config doc");
            BaseObject config = getConfigDoc(context);
            if (config != null) {
                configActiveFlag = 0 != config.getIntValue("activate");
                useCookies = 0 != config.getIntValue("useCookies");
                skipLoginPage = 0 != config.getIntValue("skipLoginPage");
                authWithCookies = 0 != config.getIntValue("authWithCookies");
                configAppName = config.getStringValue("appname").trim();
                configClientId = config.getStringValue("clientid").trim();
                configClientSecret = config.getStringValue("secret").trim();
                configDomain = config.getStringValue("domain").trim();
                if (configDomain.length() == 0) {
                    configDomain = null;
                }
                List<String> configScopes = Arrays.asList(config.getStringValue("scope").split("\\s"));
                configScopeUseAvatar = configScopes.contains(AVATAR);
                configScopeUseDrive = configScopes.contains("drive");
                configCookiesTTL = config.getIntValue("cookiesTTL");
            }
        } catch (XWikiException e) {
            e.printStackTrace();
            if (log != null) {
                log.warn("can't fetch Config doc");
            }
        }
    }

    /**
     * Reads the manifest to find when the JAR file was assembled by maven.
     *
     * @return the build date.
     * @since 3.0
     */
    @Unstable
    public Date getBuildTime()
    {
        Attributes attr = getManifestMainAttributes();
        if (attr == null) {
            return null;
        }
        return new Date(Long.parseLong(attr.getValue("Bnd-LastModified")));
    }

    /**
     * Reads the manifest to find the version of the JAR that was built.
     *
     * @return the build version
     * @since 3.0
     */
    @Unstable
    public String getBuildVersion()
    {
        Attributes attr = getManifestMainAttributes();
        if (attr == null) {
            return null;
        }
        return attr.getValue("Specification-Version");
    }

    private Attributes getManifestMainAttributes()
    {
        try {
            Class clazz = getClass();
            String className = clazz.getSimpleName()
                    + ".class";
            String classPath = clazz.getResource(className).toString();
            if (classPath != null) {
                String manifestPath = classPath.substring(0, classPath.lastIndexOf("!") + 1)
                        + "/META-INF/MANIFEST.MF";
                Manifest manifest = new Manifest(new URL(manifestPath).openStream());
                Attributes attr = manifest.getMainAttributes();
                return attr;
            } else {
                return null;
            }
        } catch (IOException e) {
            String msg = "Can't read build version.";
            log.warn(msg, e);
            throw new RuntimeException(msg, e);
        }
    }

    /**
     * Note that this dispose() will get called when this Extension is uninstalled which is the use case we want to
     * serve. The fact that it'll also be called when XWiki stops is a side effect that is ok.
     */
    @Override
    public void dispose()
    {
        XWiki xwiki = getXWiki();
        // XWiki can be null in the case when XWiki has been started and not accessed (no first request done and thus
        // no XWiki object initialized) and then stopped.
        if (xwiki != null) {
            // Unset the Authentication Service (next time XWiki.getAuthService() is called it'll be re-initialized)
            xwiki.setAuthService(null);
        }
    }

    private XWiki getXWiki()
    {
        XWiki result = null;
        XWikiContext xc = this.xwikiContextProvider.get();
        // XWikiContext could be null at startup when the Context Provider has not been initialized yet (it's
        // initialized after the first request).
        if (xc != null) {
            result = xc.getWiki();
        }
        return result;
    }

    /**
     * @return if the app is configured to use the Google Drive integration (default: yes).
     * @since 3.0
     */
    @Unstable
    public boolean isDriveEnabled()
    {
        return configScopeUseDrive;
    }

    private String getOAuthUrl()
    {
        try {
            XWikiContext context = xwikiContextProvider.get();
            DocumentReference oauthReference = new DocumentReference(context.getWikiId(),
                    SPACENAME, OAUTH);
            return getXWiki().getDocument(oauthReference, context).getExternalURL(VIEWACTION, context);
        } catch (XWikiException e) {
            throw new GoogleAppsException("Trouble at getting OAuth URL", e);
        }
    }

    private DocumentReference getXWikiUserClassRef()
    {
        return new DocumentReference(WIKINAME, XWIKISPACE, "XWikiUsers");
    }

    private String getCurrentXWikiUserName()
    {
        DocumentReference userDoc = xwikiContextProvider.get().getUserReference();
        String uName = userDoc == null ? XWIKIGUEST : userDoc.getName();
        if (XWIKIGUEST.equals(uName)) {
            uName = uName + "-" + xwikiContextProvider.get().getRequest().getSession().hashCode();
        }
        return uName;
    }

    /**
     * @param userName the name of the user
     * @return A DocumentReference for the given username.
     * @since 3.0
     */
    @Unstable
    DocumentReference createUserReference(String userName)
    {
        return userResolver.resolve(userName);
    }

    private DocumentReference getGoogleAuthClassReference()
    {
        if (gauthClassRef == null) {
            gauthClassRef = new DocumentReference(WIKINAME, SPACENAME, "GoogleAppsAuthClass");
        }
        return gauthClassRef;
    }

    private DocumentReference getSyncDocClassReference()
    {
        if (gauthClassRef == null) {
            gauthClassRef = new DocumentReference(WIKINAME, SPACENAME, "SynchronizedDocumentClass");
        }
        return gauthClassRef;
    }

    DocumentReference getConfigDocRef()
    {
        if (configDocRef == null) {
            configDocRef = new DocumentReference(WIKINAME,
                    SPACENAME, "GoogleAppsConfig");
            configObjRef = new ObjectReference("GoogleApps.GoogleAppsConfigClass", configDocRef);
        }
        return configDocRef;
    }

    /**
     * Build flow and trigger user authorization request.
     *
     * @return the configured flow
     * @throws GoogleAppsException in case something can't be built
     */
    private GoogleAuthorizationCodeFlow getFlow()
    {
        try {
            if (dsFactory == null) {
                dsFactory =
                        new FileDataStoreFactory(new java.io.File(environment.getPermanentDirectory(), SPACENAME));
            }

            // create scopes from config
            List<String> gScopes = new ArrayList<>();
            gScopes.add(PeopleServiceScopes.USERINFO_EMAIL);
            gScopes.add(PeopleServiceScopes.USERINFO_PROFILE);
            if (configScopeUseDrive != null && configScopeUseDrive) {
                gScopes.add(DriveScopes.DRIVE);
            }

            // create flow
            return new GoogleAuthorizationCodeFlow.Builder(
                    httpTransport,
                    jacksonFactory, configClientId, configClientSecret, gScopes)
                    .setDataStoreFactory(dsFactory)
                    .setAccessType("online").setApprovalPrompt(AUTOAPPROVAL)
                    .setClientId(configClientId)
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
        try {
            GoogleAuthorizationCodeFlow flow = getFlow();
            GoogleTokenResponse tokenResponse = flow
                    .newTokenRequest(authorizationCode)
                    .setRedirectUri(getOAuthUrl())
                    .execute();
            log.info("Token: " + tokenResponse);
            return flow.createAndStoreCredential(tokenResponse, getCurrentXWikiUserName());
        } catch (Exception ex) {
            throw new GoogleAppsException("Trouble at exchanging authorization code", ex);
        }
    }

    private Map<String, Credential> getCredentialStore()
    {
        final String key = "GoogleAppsCredentialStore";
        HttpSession session = xwikiContextProvider.get().getRequest().getSession(true);
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
                if (useCookies) {
                    // create a cookie
                    CookieAuthenticationPersistence cookieTools =
                            componentManager.getInstance(CookieAuthenticationPersistence.class);
                    cookieTools.setUserId(userId);
                }
            }
            log.info("Storing credentials for user " + userId);
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
                    String rtoken = credentials.getRefreshToken();
                    if (rtoken != null) {
                        log.debug("Refresh token has been created: " + rtoken);
                        storeCredentials(user, credentials);
                        return credentials;
                    } else {
                        log.debug("Failure to create refresh token");
                        storeCredentials(user, credentials);
                        return credentials;
                    }
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
                xwikiContextProvider.get().getResponse().sendRedirect(getAuthorizationURL());
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
            XWikiContext context = xwikiContextProvider.get();
            XWikiRequest request = context.getRequest();
            DocumentReference ref = context.getDoc().getDocumentReference();
            if (!(OAUTH.equals(ref.getName()) && SPACENAME.equals(ref.getLastSpaceReference().getName()))) {

                String finalRedirect = new URL(
                        new URL(getXWiki().getExternalURL("GoogleApps.Login", VIEWACTION, context)),
                        context.getDoc().getURL(VIEWACTION, request.getQueryString(), context)).toExternalForm();
                state = Integer.toHexString(finalRedirect.hashCode());
                storedStates.put(state, finalRedirect);
            }

            GoogleAuthorizationCodeRequestUrl urlBuilder = getFlow()
                    .newAuthorizationUrl()
                    .setRedirectUri(getOAuthUrl())
                    .setState(state).setClientId(configClientId)
                    .setAccessType("offline").setApprovalPrompt(AUTOAPPROVAL);
            // Add user email to filter account if the user is logged with multiple account
            if (useCookies) {
                CookieAuthenticationPersistence cookieTools =
                        componentManager.getInstance(CookieAuthenticationPersistence.class);
                String userId = cookieTools.getUserId();
                if (userId != null) {
                    XWikiDocument userDoc = getXWiki().getDocument(createUserReference(userId),
                            xwikiContextProvider.get());
                    String userEmail = null;
                    BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef(), false,
                            xwikiContextProvider.get());
                    // userclass "XWiki.XWikiUsers"

                    if (userObj != null) {
                        userEmail = userDoc.getStringValue(EMAIL);
                    }
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
     * @return found credential
     * @since 3.0
     */
    @Unstable
    public Credential authorize()
    {
        return authorize(true);
    }

    /**
     * Inspects the stored information to see if an authorization or a redirect needs to be pronounced.
     *
     * @param redirect If a redirect can be done
     * @return found credential
     * @since 3.0
     */
    @Unstable
    public Credential authorize(boolean redirect)
    {
        try {
            log.info("In authorize");
            // useless?
            GoogleAuthorizationCodeFlow flow = getFlow();
            XWikiRequest request = xwikiContextProvider.get().getRequest();
            String state = request.getParameter("state");
            XWikiResponse response = xwikiContextProvider.get().getResponse();
            Credential creds = retrieveCredentials(request.getParameter("code"), redirect);
            log.info("Got credentials: " + creds);
            if (state != null && state.length() > 0) {
                String url = storedStates.get(state);
                if (url != null) {
                    log.info("Redirecting to final destination after authorization: " + url);
                    response.sendRedirect(new URL(new URL(request.getRequestURL().toString()), url).toExternalForm());
                }
            }
            return creds;
        } catch (IOException e) {
            throw new GoogleAppsException(e);
        }
    }

    /**
     * Performs the necessary communication with Google-Services to fetch identity and update the XWiki-user object or
     * possibly sends a redirect to a Google login screen.
     *
     * @return "failed login" if failed, NOUSER (can be attempted to Google-OAuth), or "ok" if successful
     * @since 3.0
     */
    @Unstable
    public String updateUser()
    {
        try {
            if (!isActive()) {
                return FAILEDLOGIN;
            }
            log.info("Updating user...");
            XWikiContext context = xwikiContextProvider.get();
            String xwikiUser;
            Credential credential = authorize();

            Person user = null;
            if (credential != null) {
                PeopleService pservice = new PeopleService.Builder(httpTransport,
                        jacksonFactory, credential).setApplicationName(configAppName)
                        .build();
                user = pservice.people().get("people/me").setPersonFields("emailAddresses,names,photos").execute();
                // GOOGLEAPPS: User: [displayName:..., emails:[[type:account, value:...]], etag:"...",
                // id:...., image:[isDefault:false, url:https://...], kind:plus#person, language:en,
                // name:[familyName:..., givenName:...]]
            }
            log.info("user: " + user);
            String usersEmailAddress = null;
            context.getRequest().setAttribute(GOOGLEUSERATT, user);
            if (user == null) {
                return NOUSER;
            }
            if (configDomain != null) {
                boolean foundCompatibleDomain = false;
                if (user.getEmailAddresses() != null) {
                    for (EmailAddress address : user.getEmailAddresses()) {
                        String oneOfEmails = address.getValue();
                        if (oneOfEmails.endsWith(configDomain)) {
                            foundCompatibleDomain = true;
                            usersEmailAddress = oneOfEmails;
                            break;
                        }
                    }
                }
                if (!foundCompatibleDomain) {
                    String userId = getCurrentXWikiUserName();
                    getCredentialStore().remove(userId);
                    log.debug("Wrong domain: Removed credentials for userid " + userId);
                    return FAILEDLOGIN;
                }
            }
            // this seems undocumented but well working
            String id = (String) user.get("resourceName");
            String currentWiki = context.getWikiId();
            try {
                // Force main wiki database to create the user as global
                context.setMainXWiki(WIKINAME);
                if (usersEmailAddress == null) {
                    if (user.getEmailAddresses() != null && user.getEmailAddresses().size() > 0) {
                        usersEmailAddress = user.getEmailAddresses().get(0).getValue();
                    } else {
                        usersEmailAddress = "";
                    }
                }
                List<Object> wikiUserList = queryManager.createQuery(
                        "from doc.object(GoogleApps.GoogleAppsAuthClass) as auth where auth.id=:id",
                        Query.XWQL).bindValue(ID, id).execute();
                if ((wikiUserList == null) || (wikiUserList.size() == 0)) {
                    wikiUserList = queryManager.createQuery(
                            "from doc.object(XWiki.XWikiUsers) as user where user.email=:email",
                            Query.XWQL)
                            .bindValue(EMAIL, usersEmailAddress).execute();
                }

                if ((wikiUserList == null) || (wikiUserList.size() == 0)) {
                    // user not found.. need to create new user
                    xwikiUser = usersEmailAddress.substring(0, usersEmailAddress.indexOf("@"));
                    // make sure user is unique
                    xwikiUser = getXWiki().getUniquePageName(XWIKISPACE, xwikiUser, context);
                    // create user
                    DocumentReference userDirRef = new DocumentReference(
                            context.getWikiId(), "Main", "UserDirectory");
                    String randomPassword = RandomStringUtils.randomAlphanumeric(8);
                    Map<String, String> userAttributes = new HashMap<>();

                    if (user.getNames() != null && user.getNames().size() > 0) {
                        userAttributes.put(FIRSTNAME, user.getNames().get(0).getGivenName());
                        userAttributes.put(LASTNAME, user.getNames().get(0).getFamilyName());
                    }
                    userAttributes.put(EMAIL, usersEmailAddress);
                    userAttributes.put(PASSWORD, randomPassword);
                    int isCreated = getXWiki().createUser(xwikiUser, userAttributes,
                            userDirRef, null, null, "edit", context);
                    // Add google apps id to the user
                    if (isCreated == 1) {
                        log.debug("Creating user " + xwikiUser);
                        XWikiDocument userDoc = getXWiki()
                                .getDocument(createUserReference(xwikiUser), context);
                        BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());

                        // TODO: is this not redundant when having used createUser (map) ?
                        if (user.getNames() != null && user.getNames().size() > 0) {
                            userObj.set(FIRSTNAME, user.getNames().get(0).getGivenName(), context);
                            userObj.set(LASTNAME, user.getNames().get(0).getFamilyName(), context);
                        }
                        userObj.set("active", 1, context);
                        if (configScopeUseAvatar && user.getPhotos() != null
                                && user.getPhotos().size() > 0
                                && user.getPhotos().get(0).getUrl() != null)
                        {
                            String photoUrl = user.getPhotos().get(0).getUrl();
                            log.debug("Adding avatar " + photoUrl);
                            URL u = new URL(photoUrl);
                            InputStream b = u.openStream();
                            String fileName = u.getFile().substring(u.getFile().lastIndexOf('/') + 1);
                            userDoc.addAttachment(fileName, u.openStream(), context);
                            userObj.set(AVATAR, fileName, context);
                            b.close();
                        }

                        userDoc.createXObject(getGoogleAuthClassReference(), context);
                        BaseObject gAppsAuthClass = userDoc.getXObject(getGoogleAuthClassReference());
                        gAppsAuthClass.set(ID, id, context);
                        getXWiki().saveDocument(userDoc, "Google Apps login user creation", false, context);
                    } else {
                        log.debug("User creation failed");
                        return FAILEDLOGIN;
                    }
                } else {
                    // user found.. we should update it if needed
                    xwikiUser = (String) (wikiUserList.get(0));
                    log.debug("Found user " + xwikiUser);
                    boolean changed = false;
                    XWikiDocument userDoc = getXWiki().getDocument(createUserReference(xwikiUser), context);
                    BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());
                    if (userObj == null) {
                        log.debug("User found is not a user");
                        return FAILEDLOGIN;
                    } else {
                        if (!userObj.getStringValue(EMAIL).equals(usersEmailAddress)) {
                            userObj.set(EMAIL, usersEmailAddress, context);
                            changed = true;
                        }
                        if (user.getNames() != null && user.getNames().size() > 0) {
                            if (!userObj.getStringValue(FIRSTNAME).equals(
                                    user.getNames().get(0).getGivenName()))
                            {
                                userObj.set(FIRSTNAME, user.getNames().get(0).getGivenName(), context);
                                changed = true;
                            }
                            if (!userObj.getStringValue(LASTNAME).equals(
                                    user.getNames().get(0).getFamilyName()))
                            {
                                userObj.set(LASTNAME, user.getNames().get(0).getFamilyName(), context);
                                changed = true;
                            }
                        }
                        if (configScopeUseAvatar && user.getPhotos() != null && user.getPhotos().size() > 0
                                && user.getPhotos().get(0).getUrl() != null)
                        {
                            String imageUrl = user.getPhotos().get(0).getUrl();
                            imageUrl = imageUrl
                                    + (imageUrl.contains("?") ? "&" : '?')
                                    + "sz=512";
                            log.debug("Pulling avatar " + imageUrl);
                            HttpGet httpget = new HttpGet(imageUrl);
                            // TODO: add an if-modified-since
                            CloseableHttpResponse response = httpclient.execute(httpget);
                            HttpEntity entity = response.getEntity();
                            if (entity != null) {
                                ByteArrayOutputStream bOut =
                                        new ByteArrayOutputStream((int) entity.getContentLength());
                                IOUtils.copy(entity.getContent(), bOut);
                                byte[] bytesFromGoogle = bOut.toByteArray();

                                XWikiAttachment attachment =
                                        userObj.getStringValue(AVATAR) == null ? null
                                                : userDoc.getAttachment(userObj.getStringValue(AVATAR));
                                boolean fileChanged = attachment == null
                                        || attachment.getFilesize() != bytesFromGoogle.length;
                                if (!fileChanged) {
                                    byte[] b = attachment.getContent(context);
                                    for (int i = 0; i < b.length; i++) {
                                        if (b[i] != bytesFromGoogle[i]) {
                                            fileChanged = true;
                                            break;
                                        }
                                    }
                                }
                                if (fileChanged) {
                                    String fileName = imageUrl.substring(imageUrl.lastIndexOf('/') + 1);
                                    log.debug("Avatar changed " + fileName);
                                    userObj.set(AVATAR, fileName, context);
                                    userDoc.addAttachment(fileName, bytesFromGoogle, context);
                                    changed = true;
                                }
                            }
                        }

                        BaseObject googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                        if (googleAppsAuth == null) {
                            userDoc.createXObject(getGoogleAuthClassReference(), context);
                            googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                            changed = true;
                        }

                        if (!googleAppsAuth.getStringValue(ID).equals(id)) {
                            googleAppsAuth.set(ID, id, context);
                            changed = true;
                        }

                        if (changed) {
                            log.info("User changed.");
                            getXWiki().saveDocument(userDoc, "Google Apps login user updated.", context);
                        } else {
                            log.info("User unchanged.");
                        }
                    }
                }
            } catch (QueryException qe) {
                log.warn("Cannot query for users.", qe);
                throw new XWikiException("Can't query for users.", qe);
            } finally {
                // Restore database
                context.setMainXWiki(currentWiki);
            }

            // we need to restore the credentials as the user will now be logged-in
            storeCredentials(xwikiUser, credential);

            // store the validated xwiki user for the authentication module
            context.getRequest().getSession().setAttribute("googleappslogin", xwikiUser);
            return "ok";
        } catch (Exception e) {
            log.warn("Problem at updateUser", e);
            return NOUSER;
        }
    }

    /**
     * Builds and returns an authorized Drive client service.
     *
     * @return an authorized Drive client service
     */
    private Drive getDriveService()
    {
        Credential credential = authorize();
        return new Drive.Builder(
                httpTransport, jacksonFactory, credential)
                .setApplicationName(configAppName)
                .build();
    }

    /**
     * Build and return an authorized Drive client service.
     *
     * @return an authorized Drive client service
     */
    private DocsService getDocsService()
    {
        Credential credential = authorize();
        DocsService service = new DocsService(configAppName);
        service.setOAuth2Credentials(credential);
        return service;
    }

    /**
     * Get the list of all documents in the user's associated account.
     *
     * @return A list of max 10 documents.
     * @since 3.0
     */
    @Unstable
    public List<File> getDocumentList()
    {
        try {
            Drive drive = getDriveService();
            FileList result = drive.files().list().setMaxResults(10).execute();
            return result.getItems();
        } catch (IOException e) {
            throw new GoogleAppsException(e);
        }
    }

    /**
     * Fetches a list of Google Drive document matching a substring query in the filename.
     *
     * @param query     the expected query (e.g. fullText contains winter ski)
     * @param nbResults max number of results
     * @return The list of files at Google Drive.
     * @since 3.0
     */
    @Unstable
    public List<File> listDriveDocumentsWithTypes(String query, int nbResults)
    {
        try {
            Drive drive = getDriveService();
            Drive.Files.List req = drive.files().list()
                    .setQ(query)
                    .setFields("items(id,mimeType,title,exportLinks,selfLink,version,alternateLink)")
                    .setMaxResults(nbResults);
            FileList result = req.execute();
            return result.getItems();
        } catch (IOException e) {
            throw new GoogleAppsException(e);
        }
    }

    /**
     * Fetches a list of Google Drive document matching a given query.
     *
     * @param query     the expected filename substring
     * @param nbResults max number of results
     * @return The list of files at Google Drive.
     * @since 3.0
     */
    @Unstable
    public FileList listDocuments(String query, int nbResults)
    {
        try {
            Drive drive = getDriveService();
            Drive.Files.List req = drive.files().list().setQ(query).setMaxResults(nbResults);
            FileList result = req.execute();
            return result;
        } catch (IOException e) {
            throw new GoogleAppsException(e);
        }
    }

    /**
     * Fetches the google-drive document's representation and stores it as attachment.
     *
     * @param page attach to this page
     * @param name attach using this file name
     * @param id   store object attached to this attachment using this id (for later sync)
     * @param url  fetch from this URL
     * @return true if successful
     * @since 3.0
     */
    @Unstable
    public boolean retrieveFileFromGoogle(String page, String name, String id, String url)
    {
        return retrieveFileFromGoogle(getDocsService(), getDriveService(), page, name, id, url);
    }

    private boolean retrieveFileFromGoogle(DocsService docsService, Drive driveService,
            String page, String name, String id, String url)
    {
        log.info("Retrieving " + name + " to page " + page + ": " + id + url);

        try {
            XWikiDocument adoc = getXWiki().getDocument(documentResolver.resolve(page), xwikiContextProvider.get());
            byte[] data = downloadFile(docsService, url);
            saveFileToXWiki(driveService, adoc, id, name, new ByteArrayInputStream(data), true);
            return true;
        } catch (Exception e) {
            log.info(e.getMessage(), e);
            throw new GoogleAppsException("Trouble at retrieving from Google.", e);
        }
    }

    private byte[] downloadFile(DocsService docsService, String exportUrl)
    {
        try {
            MediaContent mc = new MediaContent();
            mc.setUri(exportUrl);
            MediaSource ms = docsService.getMedia(mc);

            InputStream inStream = null;
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            try {
                inStream = ms.getInputStream();

                int c;
                while ((c = inStream.read()) != -1) {
                    outStream.write(c);
                }
            } finally {
                if (inStream != null) {
                    inStream.close();
                }
                outStream.flush();
                outStream.close();
            }
            return outStream.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException("trouble at downloading document", e);
        }
    }

    private void saveFileToXWiki(Drive driveService, XWikiDocument adoc,
            String id, String name, InputStream data, boolean redirect)
    {
        try {
            XWikiContext context = xwikiContextProvider.get();
            XWikiAttachment attachment = adoc.addAttachment(name, data, context);

            // ready to save now
            adoc.saveAttachmentContent(attachment, context);

            String user = driveService.about().get().execute().getUser().getEmailAddress();
            File docData = driveService.files().get(id).execute();
            String embedLink = docData.getEmbedLink();
            if (embedLink == null) {
                embedLink = docData.getAlternateLink();
            }

            getXWiki().saveDocument(adoc, "Updated Attachment From Google Apps", context);

            BaseObject object = adoc.getXObject(getSyncDocClassReference(), FILENAME, name, false);
            if (object == null) {
                object = adoc.newXObject(getGoogleAuthClassReference(), context);
            }
            object.set(ID, id, context);
            object.set(FILENAME, name, context);
            if (context.getRequest().getParameter(URL) != null) {
                object.set(EXPORTLINK, context.getRequest().getParameter(URL), context);
            }
            object.set(VERSION, docData.getVersion().toString(), context);
            object.set(EDITLINK, docData.getAlternateLink(), context);
            object.set(EMBEDLINK, embedLink, context);
            if (object.getStringValue(USER) == null || object.getStringValue(USER).length() == 0) {
                object.set(USER, user, context);
            }
            getXWiki().saveDocument(adoc, UPDATECOMMENT, context);
            log.info("Document " + name + " has been saved to XWiki");

            if (redirect) {
                String rurl = adoc.getURL(VIEWACTION, "#Attachments", context);
                context.getResponse().sendRedirect(rurl);
            }
        } catch (Exception e) {
            throw new GoogleAppsException("Trouble at saving GoogleDrive file to XWiki.", e);
        }
    }

    /**
     * Extracts metadata about the Google Drive document corresponding to the named attachment.
     *
     * @param pageName The XWiki page where the attachment is
     * @param fileName The filename of the attachment
     * @return information about the corresponding Google Drive document
     * @since 3.0
     */
    @Unstable
    public DriveDocMetadata getGoogleDocument(String pageName, String fileName)
    {
        try {
            XWikiDocument adoc = getXWiki().getDocument(documentResolver.resolve(pageName), xwikiContextProvider.get());
            BaseObject object = adoc.getXObject(getSyncDocClassReference(), FILENAME, fileName, false);
            if (object == null) {
                return null;
            } else {
                DriveDocMetadata gdm = new DriveDocMetadata();
                gdm.id = object.getStringValue(ID);
                gdm.editLink = object.getStringValue(EDITLINK);
                gdm.exportLink = object.getStringValue(EXPORTLINK);
                return gdm;
            }
        } catch (XWikiException e) {
            throw new GoogleAppsException("Can't get Google-Document inside XWiki.", e);
        }
    }

    /**
     * Inserts the current information on the document to be embedded.
     *
     * @param docId the identifier of the Google Docs document to be embedded
     * @param doc   the XWiki document where to attach the embedding
     * @param objp  the XWiki object where this embedding is to be updated (or null if it is to be created)
     * @param nb    the number of the embedding across all the page's embeddings
     * @return the created or actualized document
     * @since 3.0
     */
    @Unstable
    public BaseObject createOrUpdateEmbedObject(String docId, XWikiDocument doc, BaseObject objp, int nb)
    {
        try {
            BaseObject obj = objp;
            Drive drive = getDriveService();
            XWikiContext context = xwikiContextProvider.get();
            String user = drive.about().get().execute().getUser().getEmailAddress();
            File docData = drive.files().get(docId).execute();
            String embedLink = docData.getEmbedLink();
            if (embedLink == null) {
                embedLink = docData.getAlternateLink();
            }

            if (obj == null) {
                obj = doc.newXObject(getSyncDocClassReference(), context);
                obj.setNumber(nb);
            }
            obj.setStringValue("id", docId);
            if (embedLink != null) {
                obj.setStringValue("embedLink", embedLink);
            }
            obj.setStringValue(EDITLINK, docData.getAlternateLink());
            obj.setStringValue(VERSION, docData.getVersion().toString());
            obj.setStringValue(FILENAME,
                    docData.getOriginalFilename() != null ? docData.getOriginalFilename() : docData.getTitle());
            obj.setStringValue(USER, user);
            getXWiki().saveDocument(doc, "Inserting Google Document", context);
            return obj;
        } catch (Exception e) {
            throw new GoogleAppsException("Can't create or update embedded document.", e);
        }
    }

    /**
     * Reads the extension and document name.
     *
     * @param docName the raw docName
     * @param elink   the link where to read the extension name
     * @return an array with extension and simplified document name
     * @since 3.0
     */
    @Unstable
    public String[] getExportLink(String docName, String elink)
    {
        int index = elink.indexOf(EXPORTFORMATEQ) + 13;
        String extension = elink.substring(index);
        String newDocName = docName
                .replaceAll("\\.(doc|docx|odt|xls|xlsx|ods|pptx|svg|png|jpeg|pdf|)$", "");
        newDocName += '.' + extension;
        return new String[]{ extension, newDocName };
    }

    private String findExportLink(String name, File entry)
    {
        String exportLink;
        String lastLink = "";
        for (Map.Entry<String, String> elink : entry.getExportLinks().entrySet()) {
            log.info("Checking link: " + elink);
            lastLink = elink.getValue();
            int index = lastLink.indexOf(EXPORTFORMATEQ) + 13;
            String extension = lastLink.substring(index);
            if (name.endsWith('.' + extension)) {
                return lastLink;
            }
        }
        int index = lastLink.indexOf(EXPORTFORMATEQ) + 13;
        exportLink = lastLink.substring(0, index);
        if (name.endsWith(".xls")) {
            exportLink += "xlsx";
        } else {
            exportLink += name.substring(name.lastIndexOf('.') + 1);
        }
        return exportLink;
    }

    /**
     * Saves the attachment stored in XWiki to the Google drive of the user attached to the current logged-in user.
     *
     * @param page the XWiki page name
     * @param name the attachment name
     * @return a record with the keys fileName, exportLink, version, editLink,  embedLink, and google-user's
     * email-address
     * @since 3.0
     */
    @Unstable
    public Map<String, Object> saveAttachmentToGoogle(String page, String name)
    {
        try {
            log.info("Starting saving attachment ${name} from page ${page}");
            XWikiContext context = xwikiContextProvider.get();
            XWikiDocument adoc = getXWiki().getDocument(documentResolver.resolve(page), context);
            XWikiAttachment attach = adoc.getAttachment(name);
            String ctype = attach.getMimeType();

            File file = new File();
            file.setTitle(name);
            file.setOriginalFilename(name);
            InputStreamContent content = new InputStreamContent(ctype, attach.getContentInputStream(context));
            Drive drive = getDriveService();
            String user = drive.about().get().execute().getUser().getEmailAddress();
            Drive.Files.Insert insert = drive.files().insert(file, content);
            insert.setConvert(true);
            File docData = insert.execute();
            if (docData != null) {
                log.info("File inserted " + docData);
                String embedLink = docData.getEmbedLink();
                if (embedLink == null) {
                    embedLink = docData.getAlternateLink();
                }

                BaseObject object = adoc.newXObject(getSyncDocClassReference(), context);
                Map<String, Object> r = new HashMap<>();
                object.set(ID, docData.getId(), context);
                r.put(ID, docData.getId());
                object.set(FILENAME, name, context);
                object.set(EXPORTLINK, findExportLink(name, docData), context);
                r.put(EXPORTLINK, findExportLink(name, docData));
                object.set(VERSION, Long.toString(docData.getVersion()), context);
                object.set(EDITLINK, docData.getAlternateLink(), context);
                r.put(EDITLINK, docData.getAlternateLink());
                object.set(EMBEDLINK, embedLink, context);
                object.set(USER, user, context);

                getXWiki().saveDocument(adoc, UPDATECOMMENT, context);
                return r;
            } else {
                log.info("File insert failed");
                return null;
            }
        } catch (Exception e) {
            throw new GoogleAppsException("Couldn't save attachment to Google.", e);
        }
    }

    /**
     * Reads the google user-info attached to the current user as stored in the request.
     *
     * @return the google user-info with keys displayName, emails (array of type,value pairs), etag, id, image (map with
     * keys isDefault and url), kind, language, name (map with keys familyName and givenName).
     * @since 3.0
     */
    @Unstable
    public Map<String, Object> getGoogleUser()
    {
        // e.g.: User: [displayName: name name,
        // emails:[[type:account, value:xxx@googlemail.com]],
        // etag:"k-5ZH5-al;sdsdkl;-sdsadsd",
        // id:948382,
        // image:[isDefault:false, url:https://222.googleusercontent.com/-2323/s50/photo.jpg],
        // kind:plus#person, language:uu,
        // name:[familyName:XXX, givenName:xxx]]
        return (Map<String, Object>) (xwikiContextProvider.get().getRequest().getAttribute(GOOGLEUSERATT));
    }
}
