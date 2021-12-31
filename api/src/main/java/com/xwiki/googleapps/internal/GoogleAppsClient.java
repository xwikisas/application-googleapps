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

import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.scribejava.apis.GoogleApi20;
import com.github.scribejava.core.builder.ServiceBuilder;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuth2AccessTokenErrorResponse;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import com.xwiki.googleapps.GoogleAppsConnections;
import com.xwiki.identityoauth.IdentityOAuthException;
import com.xwiki.identityoauth.IdentityOAuthProvider;

@Component(roles = GoogleAppsClient.class)
@Singleton
public final class GoogleAppsClient implements GoogleAppsConstants
{
    @Inject
    protected Logger logger;

    @Inject
    private Provider<GoogleAppsConnections> googleAppsConnections;

    private DefaultGoogleAppsConnections gaConn;

    private String debugInfo;

    /**
     * The connection service to the GoogleApps API.
     */
    private OAuth20Service service;

    private List<String> scopes;

    void buildService(String clientId, String secret, String usedScopes, String redir)
    {
        // avatar is used like a scope but it is not a choosable scope from Google
        // hence we exclude it before we build the client (which uses these for authorizations).
        service = new ServiceBuilder(clientId)
                .apiSecret(secret)
                .defaultScope(removeAvatar(usedScopes))
                //.httpClientConfig(ApacheHttpClientConfig.defaultConfig())
                .callback(redir)
                .build(GoogleApi20.instance());
    }

    String removeAvatar(String input)
    {
        StringBuilder r = new StringBuilder();
        for (String word : input.split(" ")) {
            if (!word.endsWith(AVATAR)) {
                r.append(word).append(' ');
            }
        }
        return r.toString();
    }

    String getAuthorizationUrl(String stateNum)
    {

        final Map<String, String> additionalParams = new HashMap<>();
        additionalParams.put("access_type", "offline");
        additionalParams.put("prompt", "consent");

        return service.createAuthorizationUrlBuilder()
                .state(stateNum).additionalParams(additionalParams).build();
    }

    void setScopes(List<String> scopes)
    {
        this.scopes = scopes;
    }

    Pair<String, Date> createToken(String authCode)
    {
        try {

            OAuth2AccessToken accessToken = service.getAccessToken(authCode);
            logger.debug("Obtained accessToken from GoogleApps Service.");
            Date expiry = new Date(System.currentTimeMillis() + 1000L * accessToken.getExpiresIn());
            return new ImmutablePair<>(accessToken.getAccessToken(), expiry);
        } catch (OAuth2AccessTokenErrorResponse e) {
            String msg = "OAuth trouble at creating token:" + e.getErrorDescription();
            logger.warn(msg, e);
            throw new IdentityOAuthException(msg, e);
        } catch (Exception e) {
            String msg = "Generic trouble at creating Token: " + e;
            logger.warn(msg, e);
            throw new IdentityOAuthException(msg, e);
        }
    }

    String readAuthorizationFromReturn(Map<String, String[]> params)
    {
        String errorDescription = "error_description";
        if (params.containsKey(errorDescription) && params.get(errorDescription).length > 0) {
            throw new IdentityOAuthException("An error occurred at GoogleApps:"
                    + " " + Arrays.asList(params.get(ERROR))
                    + " " + Arrays.asList(params.get(errorDescription)));
        }
        String codeP = "code";
        String code = params.containsKey(codeP) ? params.get(codeP)[0] : null;
        logger.debug("Obtained authorization-code from GoogleApps Services.");
        return code;
    }

    String performApiRequest(String token, String url) throws Exception
    {
        OAuthRequest request =
                new OAuthRequest(Verb.GET, url);
        service.signRequest(token, request);
        Response response = service.execute(request);
        return response.getBody();
    }

    String collectDebugInfo()
    {
        String r = debugInfo;
        debugInfo = "";
        return r;
    }

    IdentityOAuthProvider.AbstractIdentityDescription fetchIdentityDetails(String token)
    {
        try {

            OAuthRequest request;
            // we are using https://developers.google.com/people/api/rest/v1/people/get
            String url = "https://people.googleapis.com/v1/people/me?personFields=photos,names,emailAddresses";
            if (scopes.contains(SCOPE_PREFIX + AVATAR)) {
                url = url + ",photos";
            }
            request = new OAuthRequest(Verb.GET, url);
            service.signRequest(token, request);
            Response response = service.execute(request);
            String responseBody = response.getBody();
            // result is a "Person" https://developers.google.com/people/api/rest/v1/people#Person
            Map json = new ObjectMapper().readValue(responseBody, Map.class);
            GIdentityDescription iddesc = new GIdentityDescription(json);
            return iddesc;
        } catch (Exception e) {
            logger.warn("Trouble at fetchIdentityDetails:", e);
            throw new IdentityOAuthException("Trouble at fetchIdentityDetails.", e);
        }
    }

    Triple<InputStream, String, String> fetchUserImage(Date ifModifiedSince,
            IdentityOAuthProvider.AbstractIdentityDescription id, String token)
    {
        try {
            if (scopes.contains(SCOPE_PREFIX + AVATAR)) {
                OAuthRequest request;
                final List<String> supportedMediaTypes = Arrays.asList(IMAGE_JPEG, IMAGE_PNG);
                request = new OAuthRequest(Verb.GET, id.userImageUrl);
                if (ifModifiedSince != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
                    sdf.setTimeZone(TimeZone.getTimeZone("CET"));
                    String ifms = sdf.format(ifModifiedSince);
                    request.addHeader("If-Modified-Since", ifms);
                }
                logger.debug("will request " + request);
                service.signRequest(token, request);
                Response photoResponse = service.execute(request);
                String mediaType = photoResponse.getHeader("Content-Type");
                logger.debug("Request done " + mediaType);
                if (photoResponse.isSuccessful()
                        && supportedMediaTypes.contains(mediaType))
                {
                    String contentDispo = photoResponse.getHeader("Content-Disposition");
                    String fileName = "image.jpeg";
                    String at = "attachment; ";
                    if (contentDispo != null && contentDispo.startsWith(at)) {
                        fileName = contentDispo.substring(at.length());
                    }
                    logger.debug("Obtained content of file " + fileName);
                    return Triple.of(photoResponse.getStream(), IMAGE_JPEG, fileName);
                } else {
                    logger.warn("Fetching photo failed: " + photoResponse.getMessage());
                    if (logger.isDebugEnabled()) {
                        logger.debug("Photo response: " + photoResponse.getBody());
                    }
                    return null;
                }
            }
        } catch (Throwable e) {
            logger.warn("Can't save photo.", e);
        }
        return null;
    }

    SearchResult searchDocuments(String queryText)
    {
        // we are using https://developers.google.com/drive/api/v3/reference/files/list
        try {

            String baseURL = "https://developers.google.com/drive/api/v3/reference/files/list";
            if (gaConn == null) {
                gaConn = (DefaultGoogleAppsConnections) googleAppsConnections.get();
            }
            String url = SearchResult.calcSearchUrl(baseURL, queryText, gaConn);
            debugInfo += "\nSearching for " + QUOTE + queryText + QUOTE;
            Map searchResultMap = gaConn.makeApiCall(url);
            List results = (List) searchResultMap.get("files");

            throwOnPossibleError((Map) searchResultMap.get(ERROR));
            List<SearchResultItem> searchResults = new ArrayList<>(results.size());
            for (Object resO : results) {
                final Map res = (Map) resO;
                searchResults.add(new SearchResultItem(res));
            }
            return new SearchResult(SearchResult.convertSearchRes(searchResults), queryText, null);
        } catch (Exception e) {
            logger.warn("Trouble at search document.", e);
            debugInfo += "\n" + e.toString();
            return new SearchResult(null, null, e);
        }
    }

    private void throwOnPossibleError(Map errorMap)
    {
        if (errorMap != null) {
            Exception details = null;
            try {
                details = new Exception(new ObjectMapper().writeValueAsString(errorMap));
            } catch (JsonProcessingException e) {
                e.printStackTrace();
            }
            String message = "Connection to Microsoft365 failed: "
                    + errorMap.get("message");
            IdentityOAuthException ex = new IdentityOAuthException(message, details);
            ex.printStackTrace();
            throw ex;
        }
    }

    static class GIdentityDescription extends IdentityOAuthProvider.AbstractIdentityDescription
    {
        private final Map json;

        GIdentityDescription(Map jsonRecord)
        {
            this.json = jsonRecord;
            // found entries (2021-12-31): resourceName (id), etag,
            //   names (list of objects: metadata, displayName, familyName, givenName,
            //      displayNameLastFirst, unstructuredName))
            //   emailAddresses ((list of objects: metadata (object), value))

            List<Map<String, Object>> nameObj = (List<Map<String, Object>>) jsonRecord.get("names");

            firstName = nameObj.get(0).get("givenName") + "";
            lastName = nameObj.get(0).get("familyName") + "";
            internalId = (String) jsonRecord.get("resourceName");

            this.emails = grabEmailAddresses((List<Map<String, Object>>) jsonRecord.get("emailAddresses"));

            List photos = (List) json.get("photos");
            if (photos != null && photos.size() > 0) {
                userImageUrl = "" + ((Map) photos.get(0)).get("url");
            }
        }

        @Override public String getIssuerURL()
        {
            return "https://identity.google.com/";
        }
    }

    private static List<String> grabEmailAddresses(List<Map<String, Object>> emailList) {
        List<String> emailAddresses = new ArrayList<>();
        // first search for primary address
        for (Map<String, Object> email : emailList) {
            Map<String, Object> metadata = (Map<String, Object>) email.get(METADATA);
            if (metadata.containsKey(PRIMARY) && (Boolean) metadata.get(PRIMARY)) {
                emailAddresses.add(email.get(VALUE) + "");
            }
        }
        // then add all verified ones
        for (Map<String, Object> email : emailList) {
            Map<String, Object> metadata = (Map<String, Object>) email.get(METADATA);
            if (metadata.containsKey(VERIFIED) && (Boolean) metadata.get(VERIFIED)
                    && (!metadata.containsKey(PRIMARY) || (Boolean) metadata.get(PRIMARY)))
            {
                emailAddresses.add(email.get(VALUE) + "");
            }
        }
        return emailAddresses;
    }
}
