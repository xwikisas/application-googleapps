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

public interface GoogleAppsConnections
{
    /**
     * @return the URL to send the browser back to after the authentication.
     */
    String getOAuthStartUrl();

    /**
     * @return the debug information that was collected thus far.
     */
    String getDebugInfo();

    /**
     * @param macroObject the invoked macro object.
     * @return the result of running
     */
    MacroRun runMacro(Object macroObject);

    /**
     * @return the search result obtained by searching for the text in the request parameter.
     */
    SearchResult searchDocuments();

    /**
     * @return false is the session can witness that an authentication has happened with Google Apps.
     */
    boolean isMissingAuth();

    /**
     * Methods to drive the rendering of the macro.
     */
    interface MacroRun
    {
        /**
         * @return A string among displayPDF, displayEmbedIFrame, displaySearch, displaySearchResults, and displayError.
         */
        String getMode();

        /**
         * @return true if the user lacks authentication to activate the services.
         */
        boolean isAuthenticationNeeded();

        /**
         * @return true if a redirect has been requested in case of lack of authentication.
         */
        boolean isRedirecting();

        /**
         * Used when mode is displayEmbedIFrame or displayPDF.
         *
         * @return the URL to the iframe.
         */
        String getUrl();

        /**
         * Used when mode is displayEmbedIFrame or displayPDF.
         *
         * @return the width of the frame
         */
        String getWidth();

        /**
         * Used when mode is displayEmbedIFrame or displayPDF.
         *
         * @return The height of the frame
         */
        String getHeight();

        /**
         * @return the title of an error. If null or empty, the run has been successful.
         */
        String getError();

        /**
         * @return the message of the error, useful if {@link #getError()} returns non-null.
         */
        String getErrorMessage();

        /**
         * @return the number parameter or, if unavailable, the sequence number.
         */
        int getNumber();

        /**
         * @param n the number assigned to the macro
         */
        void setNumber(int n);
    }

    interface SearchResult
    {
        /**
         * @return A non-null string if an error occurred. In this case {@link #getErrorMessage()} should also return a
         * non-mepty string.
         */
        String getError();

        /**
         * @return The details of the error.
         */
        String getErrorMessage();

        List<SearchResultItem> getItems();

        /**
         * @return The text that was searched (as reported by the server).
         */
        String getSearchedText();
    }

    /**
     * A search result.
     */
    interface SearchResultItem
    {
        /**
         * @return The name (title) of the document.
         */
        String getName();

        /**
         * @return The URL to trigger an embed of the document.
         */
        String getEmbedUrl();

        /**
         * @return The name to send the user to view the document.
         */
        String getViewUrl();

        /**
         * @return the cloud internal ID of the document.
         */
        String getId();

        /**
         * @return the current version number.
         */
        String getVersion();

        /**
         * @return the expected filename.
         */
        String getFilename();
    }
}
