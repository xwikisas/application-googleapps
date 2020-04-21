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
package com.xwiki.googleapps;

import java.util.Date;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.script.service.ScriptService;
import org.xwiki.stability.Unstable;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.services.drive.model.File;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.api.Document;
import com.xpn.xwiki.api.Object;

/**
 * Script service containing the methods used by the view files contained in the ui module.
 *
 * @version $Id$
 * @since 3.0
 */
@Component
@Named("googleApps")
@Singleton
public class GoogleAppsScriptService implements ScriptService
{
    @Inject
    private GoogleAppsManager manager;

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * @return if the application is licensed and activated
     * @throws XWikiException in case a context cannot be read from thread.
     * @since 3.0
     */
    @Unstable
    public boolean isActive() throws XWikiException
    {
        return manager.isActive();
    }

    /**
     * @return if the app is configured to use the Google Drive integration (default: yes).
     * @since 3.0
     */
    @Unstable
    public boolean isDriveEnabled()
    {
        return manager.isDriveEnabled();
    }

    /**
     * Finds when the JAR file was assembled by maven.
     *
     * @return the build date.
     * @since 3.0
     */
    @Unstable
    public Date getBuildTime()
    {
        return manager.getBuildTime();
    }

    /**
     * Finds the version of the JAR file.
     *
     * @return the build version.
     * @since 3.0
     */
    @Unstable
    public String getBuildVersion()
    {
        return manager.getBuildVersion();
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
        return manager.authorize();
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
        return manager.authorize(redirect);
    }

    /**
     * Performs the necessary communication with Google-Services to fetch identity and update the XWiki-user object or
     * possibly sends a redirect to a Google login screen.
     *
     * @return "failed login" if failed, "no user" (can be attempted to Google-OAuth), or "ok" if successful
     * @since 3.0
     */
    @Unstable
    public String updateUser()
    {
        return manager.updateUser();
    }

    /**
     * Fetches a list of Google Drive document matching a substring query in the filename.
     * (used in the import function)
     *
     * @param query     the expected query (e.g. fullText contains winter ski)
     * @param nbResults max number of results
     * @return The list of {@File} at Google Drive.
     * @since 3.0
     */
    @Unstable
    public List<File> listDriveDocumentsWithTypes(String query, int nbResults)
    {
        return manager.listDriveDocumentsWithTypes(query, nbResults);
    }

    /**
     * Inserts the current information on the document to be embedded.
     *
     * @param docId the identifier of the Google Docs document to be embedded
     * @param doc   the XWiki document where to attach the embedding
     * @param obj   the XWiki object where this embedding is to be updated (or null if it is to be created)
     * @param nb    the number of the embedding across all the page's embeddings
     * @return the created or actualized document
     * @since 3.0
     */
    @Unstable
    public Object createOrUpdateEmbedObject(String docId, Document doc, Object obj, int nb)
    {
        return new Object(manager.createOrUpdateEmbedObject(docId, doc.getDocument(),
                obj == null ? null : obj.getXWikiObject(), nb),
                contextProvider.get());
    }

    /**
     * Fetches the google-drive document's representation and stores it as attachment.
     *
     * @param page attach to this page
     * @param name attach using this file name
     * @param id   store object attached to this attachment using this id (for later sync)
     * @param mediaType  content-type of the file to be fetched (or "unknown"; in this case the
     *                   mediaType is read from Tika.
     * @return true if successful
     * @since 3.0
     */
    @Unstable
    public boolean retrieveFileFromGoogle(String page, String name, String id, String mediaType)
    {
        return manager.retrieveFileFromGoogle(page, name, id, mediaType);
    }

    /**
     * Extracts metadata about the Google Drive document corresponding to the named attachment.
     *
     * @param pageName The XWiki page where the attachment is
     * @param fileName The filename of the attachment
     * @return information about the corresponding Google Drive document
     * @throws XWikiException if something happened at XWiki side
     * @since 3.0
     */
    @Unstable
    public DriveDocMetadata getGoogleDocument(String pageName, String fileName)
    {
        return manager.getGoogleDocument(pageName, fileName);
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
        return manager.getExportLink(docName, elink);
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
    public Map<String, java.lang.Object> saveAttachmentToGoogle(String page, String name)
    {
        return manager.saveAttachmentToGoogle(page, name);
    }

    /**
     * Reads the google user-info attached to the current user as stored in the request.
     *
     * @return the google user-info with keys displayName, emails (array of type,value pairs), etag, id, image (map with
     * keys isDefault and url), kind, language, name (map with keys familyName and givenName).
     * @since 3.0
     */
    @Unstable
    public Map<String, java.lang.Object> getGoogleUser()
    {
        return manager.getGoogleUser();
    }
}
