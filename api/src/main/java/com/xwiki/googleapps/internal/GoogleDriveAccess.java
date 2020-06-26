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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.tuple.Pair;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.stability.Unstable;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.http.InputStreamContent;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import com.xwiki.googleapps.DriveDocMetadata;
import com.xwiki.googleapps.GoogleAppsException;

/**
 * Tools to access the web-services of the Google Apps.
 *
 * @version $Id$
 * @since 3.0
 */
@Component(roles = GoogleDriveAccess.class)
@Singleton
public class GoogleDriveAccess implements GoogleAppsConstants, Initializable
{

    // ----- communication tools
    @Inject
    private Provider<GoogleAppsIdentity> gaIdentity;

    @Inject
    private Provider<GoogleAppsXWikiObjects> gaXWikiObjects;

    @Inject
    private Logger log;

    private JacksonFactory jacksonFactory;

    private NetHttpTransport httpTransport;

    /** Initializes the communication objects.
     * */
    public void initialize()
    {
        try {
            this.jacksonFactory = JacksonFactory.getDefaultInstance();
            this.httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException("Trouble at building GoogleDriveAccess", e);
        }
    }

    /**
     * Builds and returns an authorized Drive client service.
     *
     * @return an authorized Drive client service
     */
    private Drive getDriveService()
    {
        Credential credential = gaIdentity.get().authorize(false);
        return new Drive.Builder(
                httpTransport, jacksonFactory, credential)
                .setApplicationName(gaXWikiObjects.get().getConfigAppName())
                .build();
    }

    /**
     * Fetches a list of Google Drive document matching a substring query in the filename.
     *
     * @param query     the expected query (e.g. fullText contains winter ski)
     * @param nbResults max number of results
     * @return The list of objects documenting the Google Drive documents.
     * @since 3.0
     */
    @Unstable
    List<DriveDocMetadata> listDriveDocuments(String query, int nbResults)
    {
        try {
            Drive drive = getDriveService();
            Drive.Files.List req = drive.files().list()
                    .setFields("items(id,mimeType,title,exportLinks,selfLink,version,alternateLink)")
                    .setMaxResults(nbResults);
            if (query != null && query.length() > 0) {
                req.setQ(query);
            }
            FileList result = req.execute();
            List<File> files = result.getItems();
            List<DriveDocMetadata> r = new ArrayList<>(files.size());
            for (File file : files) {
                r.add(createDriveDocMetadata(file, null));
            }
            return r;
        } catch (IOException e) {
            throw new GoogleAppsException(e);
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
    @Unstable
    void retrieveFileFromGoogle(String page, String name, String id, String mediaType)
    {
        Drive driveService = getDriveService();
        String mt = mediaType;

        try {
            if ("unknown".equalsIgnoreCase(mediaType) || mediaType == null || !mediaType.contains("/")) {
                mt = new Tika().detect(name);
            }
            log.debug("Retrieving " + name + " to page " + page + ": " + id + "(mediatype " + mt + ").");
            InputStream downloadStream = driveService.files().export(id, mt).executeMediaAsInputStream();
            String user = driveService.about().get().execute().getUser().getEmailAddress();
            File docData = driveService.files().get(id).execute();
            createDriveDocMetadata(docData, user);
            gaXWikiObjects.get().saveFileToXWiki(page, id, name, downloadStream, createDriveDocMetadata(docData, user));
        } catch (Exception e) {
            log.info(e.getMessage(), e);
            throw new GoogleAppsException("Trouble at retrieving from Google.", e);
        }
    }

    DriveDocMetadata getEmbedData(String docId)
    {
        try {
            File docData = getDriveService().files().get(docId).execute();
            DriveDocMetadata ddm = new DriveDocMetadata();
            ddm.setId(docId);
            ddm.setEmbedLink(docData.getEmbedLink());
            if (ddm.getEmbedLink() == null) {
                ddm.setEmbedLink(docData.getAlternateLink());
            }
            ddm.setEditLink(docData.getAlternateLink());
            ddm.setFileName(
                    docData.getOriginalFilename() != null ? docData.getOriginalFilename() : docData.getTitle());
            ddm.setUser(getDriveService().about().get().execute().getUser().getEmailAddress());
            ddm.setVersion(docData.getVersion().toString());
            return ddm;
        } catch (IOException e) {
            throw new GoogleAppsException(e);
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
    @Unstable
    public DriveDocMetadata saveAttachmentToGoogle(String page, String name)
    {
        try {
            log.debug("Starting saving attachment ${name} from page ${page}");
            Pair<InputStream, String> attachPair = gaXWikiObjects.get().getAttachment(name, page);

            File file = new File();
            file.setTitle(name);
            file.setOriginalFilename(name);
            InputStreamContent content = new InputStreamContent(attachPair.getRight(), attachPair.getLeft());
            Drive drive = getDriveService();
            String user = drive.about().get().execute().getUser().getEmailAddress();
            Drive.Files.Insert insert = drive.files().insert(file, content);
            insert.setConvert(true);
            File docData = insert.execute();
            if (docData != null) {
                log.debug("File inserted " + docData);
                DriveDocMetadata ddm = createDriveDocMetadata(docData, user);
                gaXWikiObjects.get().insertSyncDocObject(page, name, ddm);
                return ddm;
            } else {
                log.warn("File insert failed");
                throw new GoogleAppsException("Google did not let us save attachment", new IOException());
            }
        } catch (Exception e) {
            throw new GoogleAppsException("Couldn't save attachment to Google.", e);
        }
    }

    private DriveDocMetadata createDriveDocMetadata(File googleFile, String userName)
    {
        DriveDocMetadata ddm = new DriveDocMetadata();
        ddm.setEmbedLink(googleFile.getEmbedLink() != null
                ? googleFile.getEmbedLink() : googleFile.getAlternateLink());
        ddm.setEditLink(googleFile.getAlternateLink());
        ddm.setVersion(Long.toString(googleFile.getVersion()));
        ddm.setFileName(googleFile.getOriginalFilename());
        if (ddm.getFileName() == null) {
            ddm.setFileName(googleFile.getTitle());
        }
        ddm.setId(googleFile.getId());
        ddm.setUser(userName);
        if (googleFile.getExportLinks() != null) {
            for (String elink : googleFile.getExportLinks().values()) {
                int index = elink.indexOf(EXPORTFORMATEQ) + 13;
                String extension = elink.substring(index);
                String newFileName = ddm.getFileName()
                        .replaceAll("\\.(doc|docx|odt|xls|xlsx|ods|pptx|svg|png|jpeg|pdf|)$", "");
                newFileName += '.' + extension;
                ddm.addExportAlternative(extension, newFileName, elink);
            }
        }
        ddm.setExportLink(googleFile.getDownloadUrl());
        return ddm;
    }
}
