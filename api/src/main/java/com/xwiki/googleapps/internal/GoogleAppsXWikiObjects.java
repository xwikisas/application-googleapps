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

import java.io.File;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.httpclient.util.DateUtil;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.environment.Environment;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.ObjectReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.query.Query;
import org.xwiki.query.QueryManager;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiAttachment;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.googleapps.DriveDocMetadata;
import com.xwiki.googleapps.GoogleAppsException;

/**
 * The objects representing the configuration of the application as well as methods to
 * connect to XWiki for the manipulation of users and attachments.
 *
 * @version $Id$
 * @since 3.0
 */
@Component(roles = GoogleAppsXWikiObjects.class)
@Singleton
public class GoogleAppsXWikiObjects implements GoogleAppsConstants, Initializable
{
    // environment
    @Inject
    private Logger log;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private QueryManager queryManager;

    @Inject
    @Named("current")
    private DocumentReferenceResolver<String> documentResolver;

    @Inject
    @Named("user")
    private DocumentReferenceResolver<String> userResolver;

    @Inject
    private Provider<GoogleAppsEventListener> eventListener;

    @Inject
    private Environment environment;

    @Inject
    private Provider<ObservationManager> observationManager;


    private File permanentDir;

    private boolean started;

    // configuration properties
    private Boolean configActiveFlag;

    private boolean useCookies;

    private boolean skipLoginPage;

    private boolean authWithCookies;

    private String configAppName;

    private String configClientId;

    private String configClientSecret;

    private String configDomain;

    private boolean configScopeUseAvatar;

    private boolean configScopeUseDrive;

    private int configCookiesTTL;

    // internal objects
    private DocumentReference configDocRef;

    private ObjectReference configObjRef;

    private DocumentReference syncdocClassRef;

    private DocumentReference gauthClassRef;

    /**
     * Initializes the internal objects.
     */
    public void initialize()
    {
        this.permanentDir = new File(environment.getPermanentDirectory(), SPACENAME);
    }

    Boolean isActive()
    {
        return configActiveFlag;
    }

    boolean doesUseCookies()
    {
        return useCookies;
    }

    boolean doesSkipLoginPage()
    {
        return skipLoginPage;
    }

    boolean doesAuthWithCookies()
    {
        return authWithCookies;
    }

    String getConfigAppName()
    {
        return configAppName;
    }

    String getConfigClientId()
    {
        return configClientId;
    }

    String getConfigClientSecret()
    {
        return configClientSecret;
    }

    String getConfigDomain()
    {
        return configDomain;
    }

    boolean getConfigScopeUseAvatar()
    {
        return configScopeUseAvatar;
    }

    boolean doesConfigScopeUseDrive()
    {
        return configScopeUseDrive;
    }

    int getConfigCookiesTTL()
    {
        return configCookiesTTL;
    }

    private BaseObject getConfigDoc(XWikiContext context)
    {
        try {
            configDocRef = getConfigDocRef();
            XWikiDocument doc = context.getWiki().getDocument(configObjRef, context);
            BaseObject result = doc.getXObject(configObjRef, false, context);
            if (result == null) {
                log.warn("Can't access Config document.");
            }
            return result;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    private DocumentReference getSyncDocClassReference()
    {
        if (syncdocClassRef == null) {
            syncdocClassRef = new DocumentReference(WIKINAME, SPACENAME, "SynchronizedDocumentClass");
        }
        return syncdocClassRef;
    }

    DocumentReference getConfigDocRef()
    {
        if (configDocRef == null) {
            configDocRef = new DocumentReference(WIKINAME,
                    SPACENAME, "GoogleAppsConfig");
            configObjRef = new ObjectReference("GoogleApps.GoogleAppsConfigClass", configDocRef);
        }
        return configDocRef;
    }

    private void readConfigDoc()
    {
        XWikiContext context = contextProvider.get();

        log.warn("Attempting to fetch Config doc");
        BaseObject config = getConfigDoc(context);
        if (config != null) {
            configActiveFlag = 0 != config.getIntValue("activate");
            useCookies = 0 != config.getIntValue("useCookies");
            skipLoginPage = 0 != config.getIntValue("skipLoginPage");
            authWithCookies = 0 != config.getIntValue("authWithCookies");
            configAppName = config.getStringValue("appname").trim();
            configClientId = config.getStringValue("clientid").trim();
            configClientSecret = config.getStringValue("secret").trim();
            configDomain = config.getStringValue("domain").trim();
            if (configDomain.length() == 0) {
                configDomain = null;
            }
            List<String> configScopes = Arrays.asList(config.getStringValue("scope").split("\\s"));
            configScopeUseAvatar = configScopes.contains(AVATAR);
            configScopeUseDrive = configScopes.contains("drive");
            configCookiesTTL = config.getIntValue("cookiesTTL");
        }
    }

    void startIfNeedBe()
    {
        if (started) {
            return;
        }
        if (eventListener == null) {
            observationManager.get().addListener(eventListener.get());
        }
        if (configActiveFlag == null || configClientId == null) {
            readConfigDoc();
        }
        started = true;
    }

    void restart()
    {
        readConfigDoc();
    }

    void saveFileToXWiki(String page,
            String driveFileId, String name, InputStream data, DriveDocMetadata ddm)
    {
        try {
            XWikiContext context = contextProvider.get();
            XWikiDocument adoc = context.getWiki().getDocument(documentResolver.resolve(page), context);
            XWikiAttachment attachment = adoc.addAttachment(name, data, context);

            // ready to save now
            adoc.saveAttachmentContent(attachment, context);

            context.getWiki().saveDocument(adoc, "Updated Attachment From Google Apps", context);

            BaseObject object = adoc.getXObject(getSyncDocClassReference(), FILENAME, name, false);
            if (object == null) {
                object = adoc.newXObject(getSyncDocClassReference(), context);
            }
            object.set(ID, driveFileId, context);
            object.set(FILENAME, name, context);
            if (context.getRequest().getParameter(URL) != null) {
                object.set(EXPORTLINK, context.getRequest().getParameter(URL), context);
            }
            object.set(VERSION, ddm.getVersion(), context);
            object.set(EDITLINK, ddm.getEditLink(), context);
            object.set(EMBEDLINK, ddm.getEmbedLink(), context);
            if (object.getStringValue(USER) == null || object.getStringValue(USER).length() == 0) {
                object.set(USER, ddm.getUser(), context);
            }
            context.getWiki().saveDocument(adoc, UPDATECOMMENT, context);
            log.info("Document " + name + " has been saved to XWiki");
        } catch (Exception e) {
            throw new GoogleAppsException("Trouble at saving GoogleDrive file to XWiki.", e);
        }
    }

    DriveDocMetadata getGoogleDocumentMetadata(String pageName, String fileName)
    {
        try {
            XWikiDocument adoc = contextProvider.get().getWiki().getDocument(documentResolver.resolve(pageName),
                    contextProvider.get());
            BaseObject object = adoc.getXObject(getSyncDocClassReference(), FILENAME, fileName, false);
            if (object == null) {
                return null;
            } else {
                DriveDocMetadata gdm = new DriveDocMetadata();
                gdm.setId(object.getStringValue(ID));
                gdm.setEditLink(object.getStringValue(EDITLINK));
                gdm.setExportLink(object.getStringValue(EXPORTLINK));
                return gdm;
            }
        } catch (Exception e) {
            throw new GoogleAppsException("Can't get Google-Document inside XWiki.", e);
        }
    }

    BaseObject createOrUpdateEmbedObject(String docId, XWikiDocument doc, BaseObject o,
            int nb, DriveDocMetadata ddm)
    {
        try {
            XWikiContext context = contextProvider.get();
            BaseObject obj = o;
            if (obj == null) {
                obj = doc.newXObject(getSyncDocClassReference(), context);
                obj.setNumber(nb);
            }
            obj.setStringValue(ID, docId);
            if (ddm.getEmbedLink() != null) {
                obj.setStringValue(EMBEDLINK, ddm.getEmbedLink());
            }

            obj.setStringValue(EDITLINK, ddm.getEditLink());
            obj.setStringValue(VERSION, ddm.getVersion());
            obj.setStringValue(FILENAME, ddm.getFileName());
            obj.setStringValue(USER, ddm.getUser());
            context.getWiki().saveDocument(doc, "Inserting Google Document", context);
            return obj;
        } catch (Exception e) {
            throw new GoogleAppsException("Couldn't update object", e);
        }
    }

    ImmutablePair<InputStream, String> getAttachment(String name, String page)
    {
        try {
            XWikiContext context = contextProvider.get();
            XWikiDocument adoc = context.getWiki().getDocument(documentResolver.resolve(page), context);
            XWikiAttachment attach = adoc.getAttachment(name);
            return new ImmutablePair<>(
                    attach.getContentInputStream(context), attach.getMimeType(context));
        } catch (Exception e) {
            throw new GoogleAppsException("Couldn't getAttachment", e);
        }
    }

    void insertSyncDocObject(String page, String name, DriveDocMetadata ddm)
    {
        try {
            XWikiContext context = contextProvider.get();
            XWikiDocument adoc = context.getWiki().getDocument(documentResolver.resolve(page), context);
            BaseObject object = adoc
                    .newXObject(getSyncDocClassReference(), context);
            object.set(ID, ddm.getId(), context);
            object.set(FILENAME, name, context);
            object.set(EXPORTLINK, ddm.getExportLink(), context);
            object.set(VERSION, ddm.getVersion(), context);
            object.set(EDITLINK, ddm.getEditLink(), context);
            object.set(EMBEDLINK, ddm.getEmbedLink(), context);
            object.set(USER, ddm.getUser(), context);

            context.getWiki().saveDocument(adoc, UPDATECOMMENT, context);
        } catch (Exception e) {
            throw new GoogleAppsException("Couldn't createSyncDocObject", e);
        }
    }

    String updateXWikiUser(String googleUserId, List<String> emails, String emailP,
            String firstName, String lastName, String avatarUrl)
    {
        XWikiContext context = contextProvider.get();
        String xwikiUser;
        String email = emailP;
        String currentWiki = context.getWikiId();
        try {
            // Force main wiki database to create the user as global
            context.setMainXWiki(WIKINAME);
            if (email == null) {
                if (emails != null && emails.size() > 0) {
                    email = emails.get(0);
                } else {
                    email = "";
                }
            }
            List<Object> wikiUserList = findExistingUser(googleUserId, email);

            if (wikiUserList == null || wikiUserList.size() == 0) {
                xwikiUser = createUser(googleUserId, email, firstName, lastName, avatarUrl, context);
            } else {
                // user found.. we should update it if needed
                xwikiUser = (String) (wikiUserList.get(0));
                if (xwikiUser.startsWith(XWIKISPACE + '.')) {
                    xwikiUser = xwikiUser.substring(XWIKISPACE.length() + 1);
                }
                updateUser(xwikiUser, email, firstName, lastName, avatarUrl, googleUserId, context);
            }
        } finally {
            // Restore database
            context.setMainXWiki(currentWiki);
        }
        return xwikiUser;
    }

    private List<Object> findExistingUser(String googleUserId, String email)
    {
        try {
            List<Object> wikiUserList = queryManager.createQuery(
                    "from doc.object(GoogleApps.GoogleAppsAuthClass) as auth where auth.id=:id",
                    Query.XWQL).bindValue(ID, googleUserId).execute();
            if ((wikiUserList == null) || (wikiUserList.size() == 0)) {
                wikiUserList = queryManager.createQuery(
                        "from doc.object(XWiki.XWikiUsers) as user where user.email=:email",
                        Query.XWQL)
                        .bindValue(EMAIL, email).execute();
            }
            return wikiUserList;
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException(e);
        }
    }

    private String createUser(String googleUserId,
            String email, String firstName, String lastName, String avatarUrl, XWikiContext context)
    {
        try {
            // user not found.. need to create new user
            String xwikiUser = email.substring(0, email.indexOf("@"));
            // make sure user is unique
            xwikiUser = context.getWiki().getUniquePageName(XWIKISPACE, xwikiUser, context);
            // create user
            DocumentReference userDirRef = new DocumentReference(
                    context.getWikiId(), "Main", "UserDirectory");
            String randomPassword =
                    Integer.toString((int) (Math.pow(10, 8)
                            + Math.floor(Math.random() * Math.pow(10, 7))), 10);
            Map<String, String> userAttributes = new HashMap<>();

            if (firstName != null) {
                userAttributes.put(FIRSTNAME, firstName);
            }
            if (lastName != null) {
                userAttributes.put(LASTNAME, lastName);
            }
            userAttributes.put(EMAIL, email);
            userAttributes.put(PASSWORD, randomPassword);
            int isCreated = context.getWiki().createUser(xwikiUser, userAttributes,
                    userDirRef, null, null, "edit", context);
            // Add google apps id to the user
            if (isCreated == 1) {
                log.debug("Creating user " + xwikiUser);
                XWikiDocument userDoc = context.getWiki()
                        .getDocument(createUserReference(xwikiUser), context);
                BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());

                userObj.set("active", 1, context);
                fetchUserImage(userDoc, userObj, avatarUrl);
                // TODO: check first and last names are written

                userDoc.createXObject(getGoogleAuthClassReference(), context);
                BaseObject gAppsAuthClass = userDoc.getXObject(getGoogleAuthClassReference());
                gAppsAuthClass.set(ID, googleUserId, context);
                context.getWiki().saveDocument(userDoc, "Google Apps login user creation", false, context);
            } else {
                log.debug("User creation failed");
                xwikiUser = null;
            }
            return xwikiUser;
        } catch (Exception e) {
            throw new GoogleAppsException(e);
        }
    }

    private void updateUser(String xwikiUser,
            String email, String firstName, String lastName, String avatarUrl, String googleUserId,
            XWikiContext context)
    {

        try {
            log.debug("Found user " + xwikiUser);
            XWikiDocument userDoc = context.getWiki().getDocument(createUserReference(xwikiUser), context);
            BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef());
            if (userObj == null) {
                log.debug("User found is not a user");
            } else {
                boolean changed = updateField(userObj, email, EMAIL, context)
                        || updateField(userObj, firstName, FIRSTNAME, context)
                        || updateField(userObj, lastName, LASTNAME, context);
                changed = changed || fetchUserImage(userDoc, userObj, avatarUrl);

                BaseObject googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                if (googleAppsAuth == null) {
                    userDoc.createXObject(getGoogleAuthClassReference(), context);
                    googleAppsAuth = userDoc.getXObject(getGoogleAuthClassReference());
                    changed = true;
                }

                changed = changed || updateField(googleAppsAuth, googleUserId, ID, context);

                if (changed) {
                    log.info("User changed.");
                    context.getWiki().saveDocument(userDoc, "Google Apps login user updated.", context);
                } else {
                    log.info("User unchanged.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new GoogleAppsException(e);
        }
    }

    private boolean updateField(BaseObject userObj, String value, String fieldName, XWikiContext context)
    {
        if (!userObj.getStringValue(fieldName).equals(value)) {
            userObj.set(fieldName, value, context);
            return true;
        } else {
            return false;
        }
    }

    private boolean fetchUserImage(XWikiDocument userDoc, BaseObject userObj,
            String imgUrl)
    {
        try {
            if (configScopeUseAvatar && imgUrl != null) {
                String imageUrl = imgUrl
                        + (imgUrl.indexOf('?') > -1 ? "&" : '?')
                        + "sz=512";
                XWikiAttachment attachment =
                        userObj.getStringValue(AVATAR) == null ? null
                                : userDoc.getAttachment(userObj.getStringValue(AVATAR));
                java.net.URL u = new URL(imageUrl);
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();

                if (attachment != null) {
                    conn.addRequestProperty("If-Modified-Since",
                            DateUtil.formatDate(attachment.getDate()));
                }

                if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    XWikiContext context = contextProvider.get();
                    log.debug("Pulling avatar " + imageUrl);

                    String fileName = imageUrl.substring(imageUrl.lastIndexOf('/') + 1);
                    if (fileName.contains("?")) {
                        fileName = fileName.substring(0, fileName.indexOf('?'));
                    }
                    log.debug("Avatar changed " + fileName);
                    userObj.set(AVATAR, fileName, context);
                    userDoc.addAttachment(fileName, conn.getInputStream(), context).setDate(
                            new Date(conn.getLastModified()));
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    DocumentReference getXWikiUserClassRef()
    {
        return new DocumentReference(WIKINAME, XWIKISPACE, "XWikiUsers");
    }

    /**
     * @param userName the name of the user
     * @return A DocumentReference for the given username.
     * @since 3.0
     */
    @Unstable
    DocumentReference createUserReference(String userName)
    {
        return userResolver.resolve(userName);
    }

    private DocumentReference getGoogleAuthClassReference()
    {
        if (gauthClassRef == null) {
            gauthClassRef = new DocumentReference(WIKINAME, SPACENAME, "GoogleAppsAuthClass");
        }
        return gauthClassRef;
    }

    File getPermanentDir()
    {
        return permanentDir;
    }

    String getUserEmail(String userId)
    {
        try {
            XWikiContext context = contextProvider.get();
            XWikiDocument userDoc = context.getWiki().getDocument(createUserReference(userId),
                    context);
            String userEmail = null;
            BaseObject userObj = userDoc.getXObject(getXWikiUserClassRef(), false,
                    context);
            // userclass "XWiki.XWikiUsers"

            if (userObj != null) {
                userEmail = userDoc.getStringValue(EMAIL);
            }
            return userEmail;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}

