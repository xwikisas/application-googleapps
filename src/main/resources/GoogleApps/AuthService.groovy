import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.lang3.StringUtils;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiUser;
import com.xpn.xwiki.user.impl.xwiki.*;

import java.security.Principal;
import org.securityfilter.realm.SimplePrincipal;
import org.securityfilter.filter.URLPatternMatcher;
import org.xwiki.container.servlet.filters.SavedRequestManager;


public class GoogleAppsAuthenticationImpl extends XWikiAuthServiceImpl {

    /**
     * Logging tool.
     */
    private static final Log LOG = LogFactory.getLog(GroovyAuthServiceImpl.class);

    public XWikiUser checkAuth(XWikiContext context) throws XWikiException {
        LOG.info("GoogleApps authentificator - checkAuth" );
        if(isLogoutRequest(context)) {
            LOG.info("caught a logout request" );
            def cookieTools = context.getWiki().parseGroovyFromPage("xwiki:GoogleApps.CookieAuthenticationPersistenceStoreTools", context)
            cookieTools.initialize(context)
            cookieTools.clear()
            LOG.info("cleared cookie" );
        }
        return super.checkAuth(context);
    }

    /**
     * We cannot authenticate locally since we need to trust the app server for
     * authentication
     *
     * @param username
     * @param password
     * @param context
     * @return
     * @throws XWikiException
     */
    public XWikiUser checkAuth(String username, String password, String rememberme, XWikiContext context) {
        return super.checkAuth(username, password, rememberme, context);
    }

    public void showLogin(XWikiContext context) throws XWikiException {
        LOG.info("GoogleApps authentificator - showLogin" );
        def redirected = false;
        try {
            def url = context.getWiki().getURL("GoogleApps.Login", "view", context)
            def configdoc = context.getWiki().getDocument("xwiki:GoogleApps.GoogleAppsConfig", context);
            def configObj = configdoc.getObject("xwiki:GoogleApps.GoogleAppsConfigClass");
            def usecookies = configObj.getStringValue("useCookies");
            def skipLoginPage = configObj.getStringValue("skipLoginPage");
            LOG.info("get cookie configuration : useCookies = " + usecookies)
            LOG.info("get cookie configuration : skipLoginPage = " + skipLoginPage)
            if (usecookies == "1" && skipLoginPage == "1") {
                LOG.info("skip the login page ")
                def request = context.getRequest();
                def cookieTools = context.getWiki().parseGroovyFromPage("xwiki:GoogleApps.CookieAuthenticationPersistenceStoreTools", context)
                cookieTools.initialize(context)
                def userCookie = cookieTools.retrieve()
                LOG.info("retrieved user from cookie : " + userCookie)
                if (userCookie) {
                    def savedRequestId = request.getParameter(SavedRequestManager.getSavedRequestIdentifier());
                    if (StringUtils.isEmpty(savedRequestId)) {
                        // Save this request
                        savedRequestId = SavedRequestManager.saveRequest(request);
                    }
                    def sridParameter = SavedRequestManager.getSavedRequestIdentifier() + "=" + savedRequestId;

                    def redirectBack = new StringBuilder(request.getRequestURI());
                    redirectBack.append('?');
                    def delimiter = "";
                    if (StringUtils.isNotEmpty(request.getQueryString())) {
                        redirectBack.append(request.getQueryString());
                        delimiter = "&";
                    }
                    if (!request.getParameterMap().containsKey(SavedRequestManager.getSavedRequestIdentifier())) {
                        redirectBack.append(delimiter);
                        redirectBack.append(sridParameter);
                    }

                    def finalURL = url + "?" + sridParameter + "&xredirect=" + URLEncoder.encode(redirectBack.toString(), "UTF-8");
                    LOG.info("Redirecting to "  + finalURL);
                    redirected = true;
                    try {
                        Utils.getComponent(Execution.class).getContext().setProperty("bypassDomainSecurityCheck", true);
                    } catch (Exception ex) {
                        LOG.error(ex);
                    }
                    context.getResponse().sendRedirect(finalURL);
                }
            }
        } catch (e) {
            LOG.error("Exception in showLogin : " + e.printStackTrace())
        } finally {
            if (!redirected)
                super.showLogin(context);
            LOG.info("GoogleApps authentificator - showLogin end" );
        }
    }

    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException {
        LOG.info("GoogleApps authentificator - authenticate" );
        def session = context.getRequest().getSession();
        def xwikiUser = session.getAttribute("googleappslogin");
        LOG.info("xwikiUser from session : " + xwikiUser)
        // get configuration for authentification with cookies
        def configdoc = context.getWiki().getDocument("xwiki:GoogleApps.GoogleAppsConfig", context);
        def configObj = configdoc.getObject("xwiki:GoogleApps.GoogleAppsConfigClass");
        def usecookies = configObj.getStringValue("useCookies");
        def authWithCookies = configObj.getStringValue("authWithCookies");
        def cookieTTL = configObj.getStringValue("cookiesTTL");
        LOG.info("get cookie configuration : useCookies = " + usecookies)
        LOG.info("get cookie configuration : authWithCookies = " + authWithCookies)
        LOG.info("get cookie configuration : cookieTTL = " + cookieTTL)
        // authenticate user from cookie value
        if (xwikiUser == null && usecookies == "1" && authWithCookies == "1") {
            LOG.info("Authenticate with cookie")
            def cookieTools = context.getWiki().parseGroovyFromPage("xwiki:GoogleApps.CookieAuthenticationPersistenceStoreTools", context)
            cookieTools.initialize(context)
            def userCookie = cookieTools.retrieve()
            LOG.info("retrieved user from cookie : " + userCookie)
            def userFullName = "xwiki:" + userCookie
            def userDoc = context.getWiki().getDocument(userFullName, context);
            xwikiUser = (userCookie == null || userDoc.isNew()) ? null : userFullName ;
            LOG.info("xwikiUser from cookie : " + xwikiUser)
        }
        if (xwikiUser!=null) {
            LOG.info("Authenticating user " + xwikiUser);
            return new SimplePrincipal(xwikiUser);
        } else {
            LOG.info("use default authenticate method for user : " + username)
            return super.authenticate(username, password, context);
        }
    }

    /**
     * @return true if the current request match the configured logout page pattern.
     */
    private boolean isLogoutRequest(XWikiContext context) {
        def logoutMatcher = context.getWiki().parseGroovyFromPage("xwiki:GoogleApps.RequestMatcherTools", context)
        logoutMatcher.initRequestMatcher(context.getWiki().Param("xwiki.authentication.logoutpage"))
        return logoutMatcher.match(context.getRequest());
    }
}
