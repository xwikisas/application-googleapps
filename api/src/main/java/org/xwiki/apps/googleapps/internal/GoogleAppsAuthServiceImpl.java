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
package org.xwiki.apps.googleapps.internal;

import java.net.URLEncoder;
import java.security.Principal;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.servlet.http.HttpSession;

import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.apps.googleapps.CookieAuthenticationPersistence;
import org.xwiki.apps.googleapps.GoogleAppsAuthService;
import org.xwiki.apps.googleapps.GoogleAppsManager;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.text.StringUtils;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * An authenticator that can include a negotiation with the Google Cloud (e.g. Google Drive) services. This
 * authenticator is created, configured and maintained by the GoogleAppsScriptService.
 *
 * @version $Id$
 * @since 3.0
 */
@Component
@InstantiationStrategy(ComponentInstantiationStrategy.PER_LOOKUP)
public class GoogleAppsAuthServiceImpl extends XWikiAuthServiceImpl
        implements GoogleAppsAuthService
{
    private static final String XWIKISPACE = "XWiki.";

    @Inject
    private Logger log;

    @Inject
    private ComponentManager componentManager;

    @Inject
    private Provider<GoogleAppsManager> googleAppsManagerProvider;

    @Inject
    @Named("xwikicfg")
    private Provider<ConfigurationSource> xwikicfgProvider;

    /**
     * Evaluates if the user can be authenticated based on request info such as cookies.
     *
     * @param context the context representign the request
     * @return a valid user, if found.
     * @throws XWikiException if anything went wrong
     */
    public XWikiUser checkAuth(XWikiContext context) throws XWikiException
    {
        try {
            log.info("GoogleApps authentificator - checkAuth");
            if (isLogoutRequest(context)) {
                log.info("caught a logout request");
                CookieAuthenticationPersistence cookieTools =
                        componentManager.getInstance(CookieAuthenticationPersistence.class);
                cookieTools.clear();
                log.info("cleared cookie");
            }
            return super.checkAuth(context);
        } catch (Exception e) {
            e.printStackTrace();
            throw new XWikiException(e.getMessage(), e);
        }
    }

    /**
     * Checks authentication.
     *
     * @param username   the name of the user to verify against
     * @param password   the password of the user to verify against
     * @param rememberme insert-cookies to remember the login
     * @param context    the context containing the request
     * @return an XWikiUser is it succeded.
     * @throws XWikiException in case something goes wrong
     */
    public XWikiUser checkAuth(String username, String password,
            String rememberme, XWikiContext context) throws XWikiException
    {
        return super.checkAuth(username, password, rememberme, context);
    }

    /**
     * Redirect user to the login.
     *
     * @param context the xwiki-context of the request
     * @throws XWikiException a wrapped exception
     */
    public void showLogin(XWikiContext context) throws XWikiException
    {
        log.info("GoogleApps authentificator - showLogin");
        if (!googleAppsManagerProvider.get().isActive()) {
            return;
        }
        boolean redirected = false;
        try {
            String url = context.getWiki().getExternalURL("GoogleApps.Login", "view", context);
            GoogleAppsManagerImpl manager = (GoogleAppsManagerImpl) googleAppsManagerProvider.get();
            if (manager.useCookies() && manager.skipLoginPage()) {
                log.info("skip the login page ");
                XWikiRequest request = context.getRequest();
                CookieAuthenticationPersistence cookieTools =
                        componentManager.getInstance(CookieAuthenticationPersistence.class);
                String userCookie = cookieTools.getUserId();
                log.info("retrieved user from cookie : " + userCookie);
                String savedRequestId = request.getParameter(
                        SavedRequestManager.getSavedRequestIdentifier());
                if (StringUtils.isEmpty(savedRequestId)) {
                    // Save this request
                    savedRequestId = SavedRequestManager.saveRequest(request);
                }
                String sridParameter = SavedRequestManager.getSavedRequestIdentifier() + "=" + savedRequestId;

                StringBuilder redirectBack = new StringBuilder(request.getRequestURI());
                redirectBack.append('?');
                String delimiter = "";
                if (StringUtils.isNotEmpty(request.getQueryString())) {
                    redirectBack.append(request.getQueryString());
                    delimiter = "&";
                }
                if (!request.getParameterMap().containsKey(SavedRequestManager.getSavedRequestIdentifier())) {
                    redirectBack.append(delimiter);
                    redirectBack.append(sridParameter);
                }

                String finalURL = url + "?" + sridParameter + "&xredirect="
                        + URLEncoder.encode(redirectBack.toString(), "UTF-8");
                log.info("Redirecting to " + finalURL);
                redirected = true;
                context.getResponse().sendRedirect(finalURL);
            }
        } catch (Exception e) {
            log.error("Exception in showLogin : " + e);
        } finally {
            if (!redirected) {
                super.showLogin(context);
            }
            log.info("GoogleApps authentificator - showLogin end");
        }
    }

    /**
     * Processes a password entry and creates the appropriate principal.
     *
     * @param username the provided user-name
     * @param password the provided password
     * @param context  the context describing the request
     * @return a null Principal Object if the user hasn't been authenticated or a valid Principal Object if the user is
     * correctly authenticated
     * @throws XWikiException if something goes wrong.
     */
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {
        try {
            log.info("GoogleApps authentificator - authenticate");

            // case of a too early call or deactivated... can only count on local users
            GoogleAppsManagerImpl googleAppsManager = (GoogleAppsManagerImpl) googleAppsManagerProvider.get();
            if (googleAppsManager == null || !googleAppsManager.isActive()) {
                return super.authenticate(username, password, context);
            }

            HttpSession session = context.getRequest().getSession();
            String xwikiUser = (String) session.getAttribute("googleappslogin");
            log.info("xwikiUser from session : " + xwikiUser);
            // get configuration for authentification with cookies

            // authenticate user from cookie value
            if (xwikiUser == null && googleAppsManager.useCookies() && googleAppsManager.authWithCookies()) {
                log.info("Authenticate with cookie");
                CookieAuthenticationPersistence cookieTools =
                        componentManager.getInstance(CookieAuthenticationPersistence.class);
                String userCookie = cookieTools.getUserId();
                if (userCookie != null) {
                    log.info("Found user from cookie : " + userCookie);
                    DocumentReference userDocRef = googleAppsManager.createUserReference(username);
                    XWikiDocument userDoc = context.getWiki().getDocument(userDocRef, context);
                    if (!userDoc.isNew()) {
                        xwikiUser = userDocRef.getName();
                    }
                    log.info("xwikiUser from cookie : " + xwikiUser);
                }
            }
            if (xwikiUser != null) {
                if (!xwikiUser.startsWith(XWIKISPACE)) {
                    xwikiUser = XWIKISPACE + xwikiUser;
                }
                log.info("Authenticating user " + xwikiUser);
                return new SimplePrincipal(xwikiUser);
            } else {
                log.info("use default authenticate method for user : " + username);
                return super.authenticate(username, password, context);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new XWikiException("Trouble at authenticating", e);
        }
    }

    private Pattern logoutRequestMatcher;

    /**
     * @return true if the current request match the configured logout page pattern.
     */
    private boolean isLogoutRequest(XWikiContext context)
    {
        if (logoutRequestMatcher == null) {
            if (xwikicfgProvider == null) {
                return false;
            }
            String patt = xwikicfgProvider.get().getProperty("xwiki.authentication.logoutpage");
            logoutRequestMatcher = Pattern.compile(patt);
        }
        return logoutRequestMatcher.matcher(context.getRequest().getPathInfo()).matches();
    }
}
