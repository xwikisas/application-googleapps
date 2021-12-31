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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.extension.ExtensionId;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.rendering.macro.wikibridge.WikiMacroParameters;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xwiki.googleapps.GoogleAppsConnections;
import com.xwiki.identityoauth.IdentityOAuthException;
import com.xwiki.identityoauth.IdentityOAuthManager;
import com.xwiki.identityoauth.IdentityOAuthProvider;
import com.xwiki.identityoauth.internal.IdentityOAuthConstants;
import com.xwiki.licensing.Licensor;

@Component
@Named("GoogleApps")
@Singleton
public class DefaultGoogleAppsConnections implements GoogleAppsConnections, IdentityOAuthProvider, GoogleAppsConstants
{
    @Inject
    protected DocumentReferenceResolver<String> documentResolver;

    @Inject
    protected Logger logger;

    @Inject
    protected Provider<Licensor> licensorProvider;

    @Inject
    protected Provider<IdentityOAuthManager> identityOAuthManager;

    @Inject
    protected MacroRunner macroRunner;

    protected DocumentReference configPageRef;

    @Inject
    private GoogleAppsClient googleClient;

    @Inject
    private Provider<XWikiContext> contextProvider;

    private ExtensionId thisExtensionId =
            new ExtensionId("com.xwiki.googleapps:googleapps");

    private List<String> scopes;

    private String redirectURL;

    private boolean active;

    private ThreadLocal<String> currentlyRequestedUrl = new ThreadLocal<>();

    private ThreadLocal<Map> currentlyObtainedJson = new ThreadLocal<>();

    @Override public void initialize(Map<String, String> config)
    {
        this.initialize(config.get("activate"), config.get("clientid"), config.get("secret"), config.get("scope"),
                config.get("redirectUrl"), config.get("configurationObjectsPage"));
    }

    /**
     * Verifies and stores the configuration parameters.
     *
     * @param activeParam a boolean saying if it is active (true/false/1)
     * @param clientId    the id of the client as provided by the Google console
     * @param secret      the secret provided by the Google console
     * @param scopesParam the space-separated list of scopes (will be added to the prefix)
     * @param redirectURL the URL to send the browser back to after authentication
     * @param configPage  the space and name of the page to store the configuration.
     */
    public void initialize(String activeParam, String clientId, String secret, String scopesParam, String redirectURL,
            String configPage)
    {
        if (scopesParam == null || scopesParam.trim().length() == 0) {
            scopes = getMinimumScopes();
        } else {
            scopes = makeScopes(scopesParam);
        }

        StringBuilder usedScopes = new StringBuilder();
        for (String s : scopes) {
            usedScopes.append(s).append(" ");
        }
        googleClient.setScopes(scopes);

        this.active = activeParam != null && (activeParam.equals("1") || Boolean.parseBoolean(activeParam));
        logger.debug("Configuring class " + this.getClass().getSimpleName()
                + " with: \n - scopes: " + scopes + "\n - clientId " + clientId);

        this.redirectURL = redirectURL;
        if (redirectURL == null || redirectURL.trim().length() == 0) {
            this.redirectURL = IdentityOAuthConstants.CHANGE_ME_LOGIN_URL;
        }

        googleClient.buildService(clientId, secret, usedScopes.toString(), this.redirectURL);

        configPageRef = documentResolver.resolve(configPage);
        logger.debug("GoogleApps-Service configured: " + this);
    }

    private List<String> makeScopes(String input)
    {

        List<String> r = new ArrayList<>();
        for (String p : input.split("[ \t\n\r]")) {
            r.add(SCOPE_PREFIX + p);
        }

        // make sure basics are in
        List<String> missing = new ArrayList<>();
        for (String m : getMinimumScopes()) {
            if (!r.contains(m)) {
                missing.add(m);
            }
        }
        if (!missing.isEmpty()) {
            throw new IdentityOAuthException("We need scopes " + getMinimumScopes() + ".");
        }
        return r;
    }

    /**
     * Verifies that the configured object is activated.
     *
     * @return true if the verification succeeded.
     */
    @Override public boolean isActive()
    {
        return active;
    }

    /**
     * Verifies that the license is current every five minutes.
     *
     * @return true if license was valid in the last five minutes.
     */
    @Override public boolean isReady()
    {
        return licensorProvider.get().hasLicensure(thisExtensionId);
    }

    @Override
    public String getProviderHint()
    {
        return GOOGLEAPPS;
    }

    @Override
    public void setProviderHint(String hint)
    {
        if (!GOOGLEAPPS.equals(hint)) {
            throw new IllegalStateException("Only \"GoogleApps\" is accepted as hint.");
        }
    }

    @Override
    public boolean isMissingAuth()
    {
        return identityOAuthManager == null || !identityOAuthManager.get().hasSessionIdentityInfo(GOOGLEAPPS);
    }

    @Override
    public String validateConfiguration()
    {
        return "ok";
    }

    @Override public List<String> getMinimumScopes()
    {
        List<String> s = new ArrayList<>();
        s.add(SCOPE_PREFIX + "userinfo.profile");
        s.add(SCOPE_PREFIX + "userinfo.email");
        // but not "drive";
        return s;
    }

    @Override public String getRemoteAuthorizationUrl(String redirectUrl)
    {
        if (!isReady()) {
            throw new IllegalStateException(EXCEPTIONUNLICENSED);
        }

        String stateNum = "xa2DJSJ" + Math.random() + "-030";
        contextProvider.get().getRequest().getSession().setAttribute(STATENUM, stateNum);

        String authorizationUrl = googleClient.getAuthorizationUrl(stateNum);
        logger.debug("Authorization URL: " + authorizationUrl);
        return authorizationUrl;
    }

    @Override public Pair<String, Date> createToken(String authCode)
    {
        if (!isReady()) {
            throw new IllegalStateException(EXCEPTIONUNLICENSED);
        }
        return googleClient.createToken(authCode);
    }

    @Override public String readAuthorizationFromReturn(Map<String, String[]> params)
    {
        if (!isReady()) {
            throw new IllegalStateException(EXCEPTIONUNLICENSED);
        }
        HttpSession session = contextProvider.get().getRequest().getSession();
        String expectedState = (String) session.getAttribute(STATENUM);
        session.removeAttribute(STATENUM);

        if (!params.containsKey(STATE)) {
            throw new IdentityOAuthException("Expecting a state parameter.");
        }
        String receivedState = params.get(STATE)[0];
        if (!receivedState.equals(expectedState)) {
            throw new IdentityOAuthException("State parameters don't match!");
        }
        return googleClient.readAuthorizationFromReturn(params);
    }

    @Override public AbstractIdentityDescription fetchIdentityDetails(String token)
    {
        if (!isReady()) {
            throw new IllegalStateException(EXCEPTIONUNLICENSED);
        }
        return googleClient.fetchIdentityDetails(token);
    }

    /**
     * Opens the stream of the user image file if it was modified later than the given date.
     *
     * @param ifModifiedSince Only fetch the file if it is modified after this date.
     * @param id              the currently collected identity-description.
     * @param token           the currently valid token.
     * @return A triple made of inputstream, media-type, and possibly guessed filename.
     */
    public Triple<InputStream, String, String> fetchUserImage(Date ifModifiedSince, AbstractIdentityDescription id,
            String token)
    {
        return googleClient.fetchUserImage(ifModifiedSince, id, token);
    }

    @Override
    public boolean enrichUserObject(AbstractIdentityDescription idDescription, XWikiDocument doc)
    {
        GoogleAppsClient.GIdentityDescription id = (GoogleAppsClient.GIdentityDescription) idDescription;
        // TODO: useful return? or definition of idDescription?
        return false;
    }

    /**
     * Method for use by sub-classes to perform signed API-calls signed by a current authorization token.
     *
     * @param url the service URL.
     * @return a map of values as parsed by a plain Jackson's {@link ObjectMapper}.
     */
    protected Map makeApiCall(String url)
    {
        Map returnValue;
        try {
            currentlyRequestedUrl.set(url);
            identityOAuthManager.get().requestCurrentToken(getProviderHint());
            returnValue = currentlyObtainedJson.get();
        } catch (Exception e) {
            if (e instanceof IdentityOAuthException) {
                throw (IdentityOAuthException) e;
            } else {
                throw new IdentityOAuthException("Trouble at API call.", e);
            }
        } finally {
            currentlyRequestedUrl.remove();
            currentlyObtainedJson.remove();
        }
        return returnValue;
    }

    /**
     * Inner part of {@link #makeApiCall(String)}, using the token.
     *
     * @param token a currently valid token used to sign the API call
     */
    @Override public void receiveFreshToken(String token)
    {
        try {
            String responseBody = googleClient.performApiRequest(token, currentlyRequestedUrl.get());
            if (logger.isDebugEnabled()) {
                logger.debug("Response received: " + responseBody);
            }
            Map json = new ObjectMapper().readValue(responseBody, Map.class);
            currentlyObtainedJson.set(json);
        } catch (Exception e) {
            throw new IdentityOAuthException("Failure at API call.", e);
        }
    }

    @Override public void setConfigPage(String page)
    {
        this.configPageRef = documentResolver.resolve(page);
    }

    @Override public String getOAuthStartUrl()
    {
        return redirectURL;
    }

    @Override public String getDebugInfo()
    {
        String r = googleClient.collectDebugInfo();
        return r;
    }

    @Override public MacroRun runMacro(Object macroObject)
    {

        Map<String, Object> mo = (Map<String, Object>) macroObject;
        WikiMacroParameters macroParams = (WikiMacroParameters) mo.get("parameters");
        return macroRunner.runMacro(macroParams);
    }

    @Override public SearchResult searchDocuments()
    {
        return googleClient.searchDocuments(contextProvider.get().getRequest().get(SEARCH_TEXT));
    }
}

