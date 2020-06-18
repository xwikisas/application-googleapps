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

import java.util.LinkedList;
import java.util.List;

import org.xwiki.stability.Unstable;

/**
 * Simple pojo for metadata about a doc in Google Drive.
 *
 * @version $Id$
 * @since 3.0
 */
@Unstable
public class DriveDocMetadata
{
    /**
     * Google's internal id to find the document again.
     */
    private String id;

    /**
     * URL to direct the user to for editing.
     */
    private String editLink;

    /**
     * URL to pull from in order to fetch the document.
     */
    private String exportLink;

    /**
     * URL to use to show an embedded view.
     */
    private String embedLink;

    /**
     * A stringified version number.
     */
    private String version;

    /**
     * The name of the file in case it is an uploaded file.
     */
    private String fileName;

    /**
     * The email-address of the user with which this document's connection was created.
     */
    private String user;

    /**
     * A list of export possibilities.
     */
    private List<ExportAlternative> exportLinksAlternatives = new LinkedList<>();

    /**
     * @return the internal Google Id of the document.
     */
    public String getId()
    {
        return id;
    }

    public void setId(String id)
    {
        this.id = id;
    }

    /**
     * @return the version number
     */
    public String getVersion()
    {
        return version;
    }

    public void setVersion(String version)
    {
        this.version = version;
    }

    /**
     * @return the URL to direct the user to for editing.
     */
    public String getEditLink()
    {
        return editLink;
    }

    public void setEditLink(String link)
    {
        this.editLink = link;
    }

    /**
     * @return the URL to pull from in order to fetch the document.
     */
    public String getExportLink()
    {
        return exportLink;
    }

    public void setExportLink(String link)
    {
        this.exportLink = link;
    }

    /**
     * @return a list of export alternatives.
     */
    public List<ExportAlternative> getExportLinksAlternatives()
    {
        return exportLinksAlternatives;
    }

    /**
     * Inserts one of the information about one of the export-alternatives.
     *
     * @param extension   the filename extension (understood as a name of the file-type)
     * @param newFileName the filename when this file is stored on a desktop with this type
     * @param exportUrl   the url to pull from.
     */
    public void addExportAlternative(String extension, String newFileName, String exportUrl)
    {
        ExportAlternative ea = new ExportAlternative();
        ea.extension = extension;
        ea.exportUrl = exportUrl;
        ea.newFileName = newFileName;
        if (ea.newFileName == null) {
            ea.newFileName = "unnamed";
        }
        exportLinksAlternatives.add(ea);
    }

    /**
     * @return the name of the file in case it is an uploaded file.
     */
    public String getFileName()
    {
        return fileName;
    }

    public void setFileName(String fileName)
    {
        this.fileName = fileName;
    }

    /**
     * @return the same as {#getFileName}.
     */
    public String getTitle()
    {
        return fileName;
    }

    /**
     * @return a useful string representation
     */
    public String toString()
    {
        return "id " + id + " edit: " + editLink + " export " + exportLink;
    }

    public String getEmbedLink()
    {
        return embedLink;
    }

    public void setEmbedLink(String link)
    {
        this.embedLink = link;
    }

    public String getUser()
    {
        return user;
    }

    public void setUser(String emailAddress)
    {
        this.user = emailAddress;
    }

    /**
     * A class to denote export possibilities of a drive file.
     */
    public static class ExportAlternative
    {
        /**
         * a short nickname of the file type, typically the file-ending.
         */
        private String extension;

        /**
         * the revised filename if exported to this extension.
         */
        private String newFileName;

        /**
         * the URL to pull from.
         */
        private String exportUrl;

        /**
         * @return a short nickname of the file type, typically the file-ending.
         */
        public String getExtension()
        {
            return extension;
        }

        /**
         * @return the revised filename if exported to this extension.
         */
        public String getNewFileName()
        {
            return newFileName;
        }

        /**
         * @return the URL to pull from.
         */
        public String getExportUrl()
        {
            return exportUrl;
        }
    }
}
