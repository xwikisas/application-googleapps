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

import java.util.List;

import org.xwiki.component.annotation.Role;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * The specification of the methods that the manager of the GoogleApps application is doing. Methods of this interface
 * are mostly called by the script-service (itself called by the views).
 *
 * @version $Id$
 * @since 3.0
 */
@Role
public interface GoogleAppsManager
{
    /**
     * @return if the application is licensed and activated
     * @throws GoogleAppsException in case a context cannot be read from thread.
     * @since 3.0
     */
    @Unstable
    boolean isActive() throws GoogleAppsException;

    /**
     * @return if the app is configured to use the Google Drive integration (default: yes).
     * @since 3.0
     */
    @Unstable
    boolean isDriveEnabled();

    /**
     * Inspects the stored information to see if an authorization or a redirect needs to be pronounced.
     *
     * @param redirect If a redirect can be done
     * @return if found a credential
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    boolean authorize(boolean redirect) throws GoogleAppsException;

    /**
     * Performs the necessary communication with Google-Services to fetch identity and update the XWiki-user object or
     * possibly sends a redirect to a Google login screen.
     *
     * @return "failed login" if failed, "no user" (can be attempted to Google-OAuth), or "ok" if successful
     * @since 3.0
     */
    @Unstable
    String updateUser();

    /**
     * Fetches a list of Google Drive document matching a substring query in the filename.
     *
     * @param query     the expected query (e.g. fullText contains winter ski)
     * @param nbResults max number of results
     * @return The list of files at Google Drive.
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    List<DriveDocMetadata> listDriveDocuments(String query, int nbResults) throws GoogleAppsException;

    /**
     * Fetches the google-drive document's representation and stores it as attachment.
     *
     * @param page      attach to this page
     * @param name      attach using this file name
     * @param id        store object attached to this attachment using this id (for later sync)
     * @param mediaType content-type of the file to be fetched (or "unknown"; in this case the mediaType is read from
     *                  Tika.
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    void retrieveFileFromGoogle(String page, String name, String id, String mediaType) throws GoogleAppsException;

    /**
     * Extracts metadata about the Google Drive document corresponding to the named attachment.
     *
     * @param pageName The XWiki page where the attachment is
     * @param fileName The filename of the attachment
     * @return information about the corresponding Google Drive document
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    DriveDocMetadata getSyncDocMetadata(String pageName, String fileName) throws GoogleAppsException;


    /**
     * Inserts the current information on the document to be embedded.
     *
     * @param docId the identifier of the Google Docs document to be embedded
     * @param doc   the XWiki document where to attach the embedding
     * @param obj   the XWiki object where this embedding is to be updated (or null if it is to be created)
     * @param nb    the number of the embedding across all the page's embeddings
     * @return the created or actualized document
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    BaseObject createOrUpdateEmbedObject(String docId, XWikiDocument doc, BaseObject obj, int nb)
            throws GoogleAppsException;

    /**
     * Saves the attachment stored in XWiki to the Google drive of the user attached to the current logged-in user.
     *
     * @param page the XWiki page name
     * @param name the attachment name
     * @return a metadata about the file
     * @throws GoogleAppsException if a communication problem with the other components occured
     * @since 3.0
     */
    @Unstable
    DriveDocMetadata saveAttachmentToGoogle(String page, String name) throws GoogleAppsException;
}
