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

import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Disposable;
import org.xwiki.component.phase.Initializable;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.googleapps.DriveDocMetadata;
import com.xwiki.googleapps.GoogleAppsException;
import com.xwiki.googleapps.GoogleAppsManager;

/**
 * Set of methods accessible to the scripts using the GoogleApps functions. The manager is the entry point for the set
 * of classes of the GoogleApps functions.
 * <p>
 * Just as other classes of this package, it is initialized as a component and thus injected with environment objects
 * such as the logger or context-provider. It is then started at its first invocation and starts the connected
 * components. This class, exposed through its interface {@GoogleAppsManager} and the authenticator functions in
 * {@GoogleAppsAuthServiceImpl} is the only one exposing public APIs.
 *
 * @version $Id$
 * @since 3.0
 */
@Component
@Singleton
public class GoogleAppsManagerImpl
        implements GoogleAppsManager, Initializable, Disposable, GoogleAppsConstants
{
    // initialisation state

    private LifeCycle lifeCycleState = LifeCycle.CONSTRUCTED;

    // own components
    @Inject
    private Provider<GoogleAppsIdentity> gaIdentity;

    @Inject
    private Provider<GoogleAppsXWikiObjects> gaXWikiObjects;

    @Inject
    private Provider<GoogleDriveAccess> gaDriveAccess;

    @Inject
    private Provider<GoogleAppsAuthService> authService;

    // ------ services from the environment
    @Inject
    private Provider<XWikiContext> xwikiContextProvider;

    @Inject
    private Logger log;

    @Override
    public void initialize()
    {
        log.info("GoogleAppsScriptService initializing (but not yet starting).");
        updateLifeCycle(LifeCycle.INITIALIZED);
    }

    // ------ own objects

    private void updateLifeCycle(LifeCycle lf)
    {
        log.info("Lifecycle to " + lf);
        lifeCycleState = lf;
    }

    private void startIfNeedBe()
    {
        if (lifeCycleState == LifeCycle.RUNNING) {
            return;
        }
        if (lifeCycleState != LifeCycle.INITIALIZED) {
            throw new IllegalStateException("Can't start when in state " + lifeCycleState + "!");
        }
        updateLifeCycle(LifeCycle.STARTING);
        boolean failed = false;

        try {
            gaXWikiObjects.get().startIfNeedBe();

            tryInittingAuthService();
        } catch (Exception e) {
            e.printStackTrace();
            failed = true;
        }

        if (!failed) {
            log.info("GoogleAppsManagerImpl is now running.");
            updateLifeCycle(LifeCycle.RUNNING);
        } else {
            updateLifeCycle(LifeCycle.INITIALIZED);
        }
    }

    void tryInittingAuthService()
    {
        XWiki xwiki = getXWiki();
        if (xwiki != null) {
            log.info("Initting authService.");
            // We do not verify with the context if the plugin is active and if the license is active
            // this will be done by the GoogleAppsAuthService and UI pages later on, when it is called within a request
            try {
                xwiki.setAuthService(authService.get());
                log.info("Succeeded initting authService,");
            } catch (Exception e) {
                log.info("Failed initting authService", e);
            }
        }
        if (authService == null) {
            log.info("Not yet initting authService.");
        }
    }

    /**
     * Evaluates weather the application is active and licensed by looking at the stored documents. Within a request,
     * this method should always be the first to be called so that the config-object is read and other properties are
     * cached if need be. The context is extracted from the thead-local.
     *
     * @return True if documents were readable, and the is licensed and active; false otherwise.
     * @since 3.0
     */
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
    boolean isActive(XWikiContext context)
    {
        startIfNeedBe();
        // move this into startIfNeedBe (and itself in xwiO?)
        if (gaIdentity == null) {
            initialize();
        }
        if (gaXWikiObjects.get().isActive() != null) {
            return gaXWikiObjects.get().isActive();
        }
        return false;
    }

    /**
     * @return true if the app is configured to use cookies to store the association to the Google user.
     * @since 3.0
     */
    public boolean useCookies()
    {
        return gaXWikiObjects.get().doesUseCookies();
    }

    /**
     * @return true if the app is configured to simply use the cookie and thus recognize the user based on cookie
     * @since 3.0
     */
    public boolean skipLoginPage()
    {
        return gaXWikiObjects.get().doesSkipLoginPage();
    }

    /**
     * @return true if the app is configured to use cookies to store the association to the Google user
     * @since 3.0
     */
    public boolean authWithCookies()
    {
        return gaXWikiObjects.get().doesAuthWithCookies();
    }

    /**
     * @return if the app is configured to use the Google Drive integration (default: yes).
     * @since 3.0
     */
    public boolean isDriveEnabled()
    {
        return gaXWikiObjects.get().doesConfigScopeUseDrive();
    }

    /**
     * Note that this dispose() will get called when this Extension is uninstalled which is the use case we want to
     * serve. The fact that it'll also be called when XWiki stops is a side effect that is ok.
     */
    @Override
    public void dispose()
    {
        updateLifeCycle(LifeCycle.STOPPING);
        XWiki xwiki = getXWiki();
        // XWiki can be null in the case when XWiki has been started and not accessed (no first request done and thus
        // no XWiki object initialized) and then stopped.
        if (xwiki != null) {
            // Unset the Authentication Service (next time XWiki.getAuthService() is called it'll be re-initialized)
            xwiki.setAuthService(null);
        }
        updateLifeCycle(LifeCycle.STOPPED);
    }

    XWiki getXWiki()
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
     * Performs the necessary communication with Google-Services to fetch identity and update the XWiki-user object or
     * possibly sends a redirect to a Google login screen.
     *
     * @return "failed login" if failed, {@NOUSER} (can be attempted to Google-OAuth), or "ok" if successful
     * @since 3.0
     */
    public String updateUser()
    {
        return gaIdentity.get().updateUser();
    }

    /**
     * Inspects the stored information to see if an authorization or a redirect needs to be pronounced.
     *
     * @param redirect If a redirect can be done
     * @return if found a credential
     * @since 3.0
     */
    public boolean authorize(boolean redirect)
    {
        try {
            return null != gaIdentity.get().authorize(redirect);
        } catch (Exception ex) {
            log.warn("Trouble at authorizing", ex);
            return false;
        }
    }

    /**
     * Fetches the google-drive document's representation and stores it as attachment.
     *
     * @param page      attach to this page
     * @param name      attach using this file name
     * @param id        store object attached to this attachment using this id (for later sync)
     * @param mediaType content-type of the file to be fetched (or "unknown"; in this case the mediaType is read from
     *                  Tika.
     * @since 3.0
     */
    public void retrieveFileFromGoogle(String page, String name, String id, String mediaType)
    {
        gaDriveAccess.get().retrieveFileFromGoogle(page, name, id, mediaType);
    }

    /**
     * Extracts metadata about the Google Drive document corresponding to the named attachment.
     *
     * @param pageName The XWiki page where the attachment is
     * @param fileName The filename of the attachment
     * @return information about the corresponding Google Drive document
     * @since 3.0
     */
    public DriveDocMetadata getSyncDocMetadata(String pageName, String fileName)
    {
        return gaXWikiObjects.get().getGoogleDocumentMetadata(pageName, fileName);
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
    public BaseObject createOrUpdateEmbedObject(String docId, XWikiDocument doc, BaseObject objp, int nb)
    {
        try {

            DriveDocMetadata ddm = gaDriveAccess.get().getEmbedData(docId);
            // use here and at retrieveFromGoogle
            return gaXWikiObjects.get().createOrUpdateEmbedObject(docId, doc, objp, nb, ddm);
        } catch (Exception e) {
            throw new GoogleAppsException("Can't create or update embedded document.", e);
        }
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
    public DriveDocMetadata saveAttachmentToGoogle(String page, String name)
    {
        return gaDriveAccess.get().saveAttachmentToGoogle(page, name);
    }

    /**
     * Fetches a list of Google Drive document matching a substring query in the filename.
     *
     * @param query     the exfpected query (e.g. fullText contains winter ski)
     * @param nbResults max number of results
     * @return The list of objects of Google Drive.
     * @since 3.0
     */
    public List<DriveDocMetadata> listDriveDocuments(String query, int nbResults)
    {
        startIfNeedBe();
        return gaDriveAccess.get().listDriveDocuments(query, nbResults);
    }

    enum LifeCycle
    { CONSTRUCTED, INITIALIZED, STARTING, RUNNING, STOPPING, STOPPED }
}
