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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.velocity.tools.generic.EscapeTool;

import com.xwiki.googleapps.GoogleAppsConnections;

/**
 * POJO to describe the result of a search.
 */
class SearchResult implements GoogleAppsConnections.SearchResult, GoogleAppsConstants
{
    private List<GoogleAppsConnections.SearchResultItem> items;

    private String error;

    private String message;

    private String searchedText;

    SearchResult(List<GoogleAppsConnections.SearchResultItem> items, String searchedText, Exception ex)
    {
        this.items = items;
        if (ex != null) {
            this.error = ex.getMessage();
            Throwable cause = ex.getCause();
            if (cause != null) {
                this.message = cause.getMessage();
            }
        }
        this.searchedText = searchedText;
        this.error = error;
        this.message = message;
    }

    static List<GoogleAppsConnections.SearchResultItem> convertSearchRes(List<SearchResultItem> items)
    {
        List<GoogleAppsConnections.SearchResultItem> i = new ArrayList<>(items.size());
        i.addAll(items);
        return i;
    }

    public static String calcSearchUrl(String baseURL, String queryText, DefaultGoogleAppsConnections gaConn)
    {
        String text = queryText;

        Map<String, String> queryParams = new HashMap<>();

        queryParams.put("field", "id,mimeType,title,exportLinks,webViewLink,version");
        queryParams.put("pageSize", "100");
        queryParams.put("corpora", "allDrives");
        // make it possible to finish the query by giving e.g. "orderBy name" at the end of the query
        if (text.matches(".* " + ORDERBY + " [a-zA-Z]+")) {
            queryParams.put(ORDERBY, text.substring(text.lastIndexOf(' ') + 1));
            // remove two last words form text
            text = text.substring(0, text.lastIndexOf(' '));
            text = text.substring(0, text.lastIndexOf(' '));
        } else {
            queryParams.put(ORDERBY, "viewedByMeTime");
        }

        if (text != null && text.length() > 0) {
            if (text.contains(APOSTROPHE)) {
                if (!text.contains(" contains ") && !text.contains("=")
                        && !text.contains(" in ") && !text.contains(">"))
                {
                    text = text.replaceAll(APOSTROPHE, "\\'");
                }
            }
            text = "fulltext contains '" + text + "'";
            queryParams.put("q", text);
        }
        EscapeTool escapeTool = new EscapeTool();

        // we need a token so we request the googleApps connection to make the api call for us
        // this will call us but with a possibly refreshed token
        StringBuilder url = new StringBuilder(baseURL);
        url.append("?");
        for (Map.Entry<String, String> entry : queryParams.entrySet()) {
            url.append(entry.getKey()).append('=').append(escapeTool.url(entry.getValue()));
        }
        return url.toString();
    }

    /**
     * @return A non-null string if an error occurred. In this case {@link #getErrorMessage()} should also return a
     * non-mepty string.
     */
    public String getError()
    {
        return error;
    }

    /**
     * @return The details of the error.
     */
    public String getErrorMessage()
    {
        return message;
    }

    public List<GoogleAppsConnections.SearchResultItem> getItems()
    {
        return items;
    }

    /**
     * @return The text that was searched (as reported by the server).
     */
    public String getSearchedText()
    {
        return searchedText;
    }
}

class SearchResultItem implements GoogleAppsConnections.SearchResultItem, GoogleAppsConstants
{
    private Map res;

    SearchResultItem(Map r)
    {
        this.res = r;
    }

    public String getName()
    {
        return (String) res.get(NAME);
    }

    public String getEmbedUrl()
    {
        return getViewUrl();
    }

    public String getViewUrl()
    {
        return (String) res.get("webViewLink");
    }

    public String getId()
    {
        return ((String) res.get("id"));
    }

    public String getVersion()
    {
        return ((String) res.get("version"));
    }

    public String getFilename()
    {
        return (String) res.get(NAME);
    }
}
