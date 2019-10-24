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
package org.xwiki.apps.googleapps;


import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.XWikiRequest;

import java.net.URLEncoder;
import java.security.Principal;
import java.util.regex.Pattern;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;

import org.securityfilter.realm.SimplePrincipal;
import org.slf4j.Logger;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.container.servlet.filters.SavedRequestManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.text.StringUtils;

/**
 * An authenticator that can include a negotiation with the Google Cloud (e.g. Google Drive) services.
 * This authenticator is created, configured and maintained by the GoogleAppsScriptService.
 * @since 2.5-RC1
 * @version $Id$
 */
public class GoogleAppsAuthService extends XWikiAuthServiceImpl
{

    GoogleAppsAuthService(GoogleAppsScriptService father, Logger log) {
        if (this.log == null) {
            this.log = log;
        }
        this.scriptService = father;
        log.info("GoogleApps authentificator - constructed (" + father + ").");
    }

    @NotNull
    private GoogleAppsScriptService scriptService;

    private Logger log;


    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        try {
            log.info("GoogleApps authentificator - checkAuth");
            if (isLogoutRequest(context)) {
                log.info("caught a logout request");
                CookieAuthenticationPersistenceStoreTools cookieTools =
                        new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                cookieTools.clear();
                log.info("cleared cookie");
            }
            return super.checkAuth(context);
        } catch (Exception e) {
            e.printStackTrace();
            throw new XWikiException(e.getMessage(), e);
        }
    }

    public XWikiUser checkAuth(String username, String password,
            String rememberme, XWikiContext context) throws XWikiException  {
        return super.checkAuth(username, password, rememberme, context);
    }



    /**
     * Redirect user to the login.
     *
     * @param context the xwiki-context of the request
     * @throws XWikiException a wrapped exception
     */
    public void showLogin(XWikiContext context) throws XWikiException {
        log.info("GoogleApps authentificator - showLogin");
        if (!scriptService.isActive(context)) {
            return;
        }
        boolean redirected = false;
        try {
            String url = context.getWiki().getURL("GoogleApps.Login", "view", context);
            if (scriptService.isUseCookies() && scriptService.isSkipLoginPage()) {
                log.info("skip the login page ");
                XWikiRequest request = context.getRequest();
                CookieAuthenticationPersistenceStoreTools cookieTools =
                        new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                String userCookie = cookieTools.retrieve();
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
                log.info("Redirecting to "  + finalURL);
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

    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException {
        try {
            log.info("GoogleApps authentificator - authenticate");

            // case of a too early call or deactivated... can only count on local users
            if (scriptService == null || !scriptService.isActive(context)) {
                return super.authenticate(username, password, context);
            }

            HttpSession session = context.getRequest().getSession();
            String xwikiUser = (String) session.getAttribute("googleappslogin");
            log.info("xwikiUser from session : " + xwikiUser);
            // get configuration for authentification with cookies

            // authenticate user from cookie value
            if (xwikiUser == null && scriptService.isUseCookies() && scriptService.isAuthWithCookies()) {
                log.info("Authenticate with cookie");
                CookieAuthenticationPersistenceStoreTools cookieTools =
                        new CookieAuthenticationPersistenceStoreTools();
                cookieTools.initialize(context);
                String userCookie = cookieTools.retrieve();
                if (userCookie != null) {
                    log.info("retrieved user from cookie : " + userCookie);
                    DocumentReference userDocRef = scriptService.createUserReference(username);
                    XWikiDocument userDoc = context.getWiki().getDocument(userDocRef, context);
                    if (!userDoc.isNew())  {
                        xwikiUser = userDocRef.getName();
                    }
                    log.info("xwikiUser from cookie : " + xwikiUser);
                }
            }
            if (xwikiUser != null) {
                if (!xwikiUser.startsWith("XWiki.")) {
                    xwikiUser = "XWiki." + xwikiUser;
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

    @Inject
    @Named("xwikicfg")
    private Provider<ConfigurationSource> xwikicfgProvider;

    /**
     * @return true if the current request match the configured logout page pattern.
     */
    private boolean isLogoutRequest(XWikiContext context) {
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
