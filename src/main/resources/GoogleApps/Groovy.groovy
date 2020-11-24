import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.googleapis.auth.oauth2.*;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.FileDataStoreFactory;

import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.Drive;
import org.apache.tika.Tika;

import com.google.api.client.http.ByteArrayContent;

import com.google.api.services.people.v1.PeopleService;
import com.google.api.services.people.v1.PeopleServiceScopes;
import com.google.api.services.people.v1.model.EmailAddress;
import com.google.api.services.people.v1.model.Person;

import org.xwiki.environment.Environment;
import com.xpn.xwiki.web.Utils;

import org.apache.velocity.tools.generic.EscapeTool;
import org.apache.commons.lang.RandomStringUtils;
import com.xpn.xwiki.api.*;

public class GoogleAppsGroovy {

// Config Page
    def CONFIG_PAGE = "GoogleApps.GoogleAppsConfig";
    def CONFIG_CLASS = "GoogleApps.GoogleAppsConfigClass";
    def FEED_URL = "https://www.googleapis.com/drive/v2/files";

// is Application Active
    def active = false;

// Cookies configuration
    def useCookies = false;
    def skipLoginPage = false;
    def authWithCookies = false;
    def cookiesTTL = 0;
    def useAvatar = false, useDrive = false;

    def APPNAME;
    def CLIENTID;
    def SECRET;
    def SCOPE;
    def DOMAIN;
    def AUTH_PAGE = "GoogleApps.OAuth";
    def DATA_DIR = "googleapps"
    def REDIRECT_URI;

// xwiki variables
    XWiki xwiki;
    Context context;
    Document doc;
    def request;
    def response;
    def services;
    def googleUser;

    public static storedCredentials = new HashMap();
    public static storedStates = new HashMap();

    def escapetool = new EscapeTool();
    def sdebug = new StringBuffer();

    def DATA_STORE_FILE = new File(Utils.getComponent(Environment.class).getPermanentDirectory(), DATA_DIR);

/** Global instance of the {@link FileDataStoreFactory}. */
    def DATA_STORE_FACTORY = new FileDataStoreFactory(DATA_STORE_FILE);

    def JSON_FACTORY = JacksonFactory.getDefaultInstance();

/** Global instance of the HTTP transport. */
    def HTTP_TRANSPORT = GoogleNetHttpTransport.newTrustedTransport();

/** Global instance of the scopes required by this quickstart. */
    def SCOPES = new ArrayList();

    public getConfig(name) {

        def config = "";
        def configdoc = xwiki.getDocument(CONFIG_PAGE);
        configdoc.use(CONFIG_CLASS);
        def obj = configdoc.getDocument().getObject(CONFIG_CLASS);
        if (obj!=null) {
            config = (obj.get(name)!=null) ? obj.get(name).getValue() : "";
        }
        if (config=="") {
            configdoc = xwiki.getDocument("xwiki:" + CONFIG_PAGE);
            configdoc.use(CONFIG_CLASS);
            obj = configdoc.getDocument().getObject(CONFIG_CLASS);
            if (obj!=null) {
                config = (obj.get(name)!=null) ? obj.get(name).getValue() : "";
            }
        }
        return config;
    }

    public init(xwiki, context, doc) {
        init(xwiki, context, doc, null)
    }

    public init(XWiki xwiki, context, doc, services) {
        this.xwiki = xwiki;
        this.context = context;
        this.doc = doc;
        this.services = services;

        this.request = context.request;
        this.response = context.response;


        this.APPNAME  = getConfig("appname");
        this.CLIENTID  = getConfig("clientid").trim();
        this.SECRET  = getConfig("secret").trim();
        this.SCOPE  = getConfig("scope");
        this.DOMAIN  = getConfig("domain");
        this.active  = getConfig("active");
        this.REDIRECT_URI = xwiki.getDocument(AUTH_PAGE).getExternalURL("view");
        this.useCookies = getConfig("useCookies");
        this.skipLoginPage = getConfig("skipLoginPage");
        this.authWithCookies = getConfig("authWithCookies");
        this.cookiesTTL = getConfig("cookiesTTL");
        this.useAvatar = this.SCOPE.contains("avatar");
        this.useDrive = this.SCOPE.contains("drive");

        // adding user profile scopes
        // SCOPES.add(PlusScopes.PLUS_LOGIN);
        SCOPES.add(PeopleServiceScopes.USERINFO_EMAIL);
        SCOPES.add(PeopleServiceScopes.USERINFO_PROFILE);
        if(useDrive)  {
            SCOPES.addAll(Arrays.asList(DriveScopes.DRIVE));
        }

        addDebug("APPNAME: ${APPNAME}");
        addDebug("CLIENTID: ${CLIENTID}");
        addDebug("SCOPE: ${SCOPES}");
    }

    public addDebug(str) {
        sdebug.append(str);
        sdebug.append("\n");
        System.println("GOOGLEAPPS: ${str}");
    }

    public getDebug() {
        return sdebug.toString();
    }

    public isActive() {
        return active;
    }

    def getFlow() {
        // Build flow and trigger user authorization request.
        GoogleAuthorizationCodeFlow flow =
                new GoogleAuthorizationCodeFlow.Builder(
                        HTTP_TRANSPORT, JSON_FACTORY, CLIENTID, SECRET, SCOPES)
                        .setDataStoreFactory(DATA_STORE_FACTORY)
                        .setClientId(CLIENTID)
                        .setAccessType("online").setApprovalPrompt("auto")
                        .build();
        return flow;
    }

    /**
     * Exchange an authorization code for OAuth 2.0 credentials.
     *
     * @param authorizationCode Authorization code to exchange for OAuth 2.0
     *     credentials.
     * @return OAuth 2.0 credentials.
     */
    def exchangeCode(String authorizationCode) {
        try {
            def flow = getFlow();
            def tokenResponse = flow
                    .newTokenRequest(authorizationCode)
                    .setRedirectUri(REDIRECT_URI)
                    .execute();
            addDebug("Token: " + tokenResponse)
            return flow.createAndStoreCredential(tokenResponse, context.user);
        } catch (e) {
            addDebug("An error occurred: " + e);
            e.printStackTrace();
            return null;
        }
    }

    def storeCredentials(userId, credentials) {
        if (userId.contains("XWiki.XWikiGuest")) {
            userId = userId + "-" + request.getSession().getId();
        }
        else {
            if (useCookies) {
                // create a cookie
                def cookieTools = xwiki.parseGroovyFromPage("xwiki:GoogleApps.CookieAuthenticationPersistenceStoreTools")
                if(cookiesTTL) {
                    cookieTools.initialize(context.context, Integer.parseInt(cookiesTTL))
                }
                else {
                    cookieTools.initialize(context.context)
                }
                cookieTools.store(userId)
                addDebug("Store cookie for user " + userId)
            }
        }
        addDebug("Storing credentials for user " + userId);
        return storedCredentials.put(userId, credentials);
    }
    def getStoredCredentials(userId) {
        if (userId.contains("XWiki.XWikiGuest")) {
            userId = userId + "-" + request.getSession().getId();
        }
        addDebug("Getting credentials for user " + userId);
        return storedCredentials.get(userId);
    }

/**
 * Retrieve credentials using the provided authorization code.
 *
 * This function exchanges the authorization code for an access token and
 * queries the UserInfo API to retrieve the user's e-mail address. If a
 * refresh token has been retrieved along with an access token, it is stored
 * in the application database using the user's e-mail address as key. If no
 * refresh token has been retrieved, the function checks in the application
 * database for one and returns it if found or throws a NoRefreshTokenException
 * with the authorization URL to redirect the user to.
 *
 * @param authorizationCode Authorization code to use to retrieve an access
 *     token.
 * @param state State to set to the authorization URL in case of error.
 * @return OAuth 2.0 credentials instance containing an access and refresh
 *     token.
 * @throws IOException Unable to load client_secret.json.
 */
    def getCredentials(String authorizationCode) throws IOException {
        return getCredentials(authorizationCode, true);
    }

    def getCredentials(String authorizationCode, redirect)
            throws IOException {
        Credential credentials = null;

        if (authorizationCode!=null && authorizationCode!="") {
            addDebug("Trying to get credentials from authorization code: ${authorizationCode}");
            credentials = (authorizationCode==null) ? null : exchangeCode(authorizationCode);
            if (credentials!=null) {
                def rtoken = credentials.getRefreshToken();
                if (rtoken != null) {
                    addDebug("Refresh token has been created: " + rtoken);
                    storeCredentials(context.user, credentials);
                    return credentials;
                } else {
                    addDebug("Failure to create refresh token");
                    storeCredentials(context.user, credentials);
                    return credentials;
                }
            }
        }

        if (credentials==null) {
            addDebug("No credentials found. Checking stored credentials for user " + context.user);
            credentials = getStoredCredentials(context.user);
            if (credentials != null) {
                addDebug("Retrieved stored credentials");
                return credentials;
            }
            addDebug("Could not find stored credentials");
        }

        addDebug("No credentials retrieved.");
        // No refresh token has been retrieved.
        if (redirect) {
            addDebug("Redirecting to authorization URL.");
            response.sendRedirect(getAuthorizationURL());
        }
    }


    def getAuthorizationURL() {
        def state = "";
        if (doc.fullName!="GoogleApps.OAuth") {
            def finalRedirect = request.getRequestURL().toString();
            def qs = request.getQueryString();
            if (qs!=null & qs!="")
                finalRedirect += "?" + qs;
            state = finalRedirect.hashCode().toString();
            storedStates.put(state, finalRedirect);
        }

        def urlBuilder = getFlow()
                .newAuthorizationUrl()
                .setRedirectUri(REDIRECT_URI)
                .setState(state).setClientId(CLIENTID)
                .setAccessType("offline").setApprovalPrompt("auto");
        // Add user email to filter account if the user is logged with multiple account
        if (useCookies) {
            def cookieTools = xwiki.parseGroovyFromPage("xwiki:GoogleApps.CookieAuthenticationPersistenceStoreTools")
            cookieTools.initialize(context.context)
            def userId = cookieTools.retrieve()
            def userDoc = xwiki.getDocumentAsAuthor("xwiki:" + userId)
            def userEmail = null;
            if (userDoc.getObject("XWiki.XWikiUsers")) {
                userDoc.use("XWiki.XWikiUsers")
                userEmail = userDoc.getValue("email")
            }
            if(userEmail) {
                urlBuilder = urlBuilder.set("login_hint", userEmail);
            }
        }
        def authurl = urlBuilder.build();
        addDebug("google authentication url : " + authurl)
        return authurl
    }

    def authorize() throws IOException {
        return authorize(true);
    }

    def authorize(redirect) throws IOException {
        addDebug("In authorize")
        def flow = getFlow();
        def creds = getCredentials(request.code, redirect);
        addDebug("Got credentials: ${creds}")
        if (request.state && request.state!="") {
            def url = storedStates.get(request.state);
            if (url!=null) {
                addDebug("Redirecting to final destination after authorization: ${url}")
                response.sendRedirect(url)
            }
        }
        return creds;
    }

    def updateUser() {
        addDebug("Updating User ");
        if(CLIENTID==null || CLIENTID.trim().length()==0 ||
                SECRET==null || SECRET.trim().length()==0) {
            return -1;
        }
        def xwikiUser = null, user = null;
        def credential = authorize();
        if (credential == null) return -1;

        try {
            PeopleService pservice = new PeopleService.Builder(HTTP_TRANSPORT,
                    JSON_FACTORY, credential).setApplicationName(APPNAME)
                    .build();
            user = pservice.people().get("people/me").setPersonFields("emailAddresses,names,photos").execute();
            this.googleUser = user;
            addDebug("user: " + user);
        } catch (Exception ex) {
            addDebug("Error when pulling user information: ${ex}.");
            ex.printStackTrace();
            return null;
        }
        String usersEmailAddress = "";
        // GOOGLEAPPS: User: [displayName:Paul Libbrecht, emails:[[type:account, value:paul.libbrecht@googlemail.com]], etag:"k-5ZH5-QJvSewqvyYHTE9ETORZg/EbrzZ-WXep7ocoOnw7mPH3ohUF0", id:108124822654357414762, image:[isDefault:false, url:https://lh5.googleusercontent.com/-ozemnElunF0/AAAAAAAAAAI/AAAAAAAACGw/oyQfa2rA1YM/s50/photo.jpg], kind:plus#person, language:en, name:[familyName:Libbrecht, givenName:Paul]]
        if (user==null) {
            return null;
        }
        if (DOMAIN!="") {
            boolean foundCompatibleDomain = false;
            if(user.getEmailAddresses() != null) {
                for(EmailAddress address: user.getEmailAddresses()) {
                    String addr = address.getValue();
                    if(addr.endsWith(DOMAIN)) {
                        foundCompatibleDomain = true;
                        usersEmailAddress = addr;
                        break;
                    }
                }
            }
            if(!foundCompatibleDomain) {
                def userId = context.user + "-" + request.getSession().getId();
                storedCredentials.remove(userId);
                addDebug("Wrong domain: Removed credentials for userid " + userId)
                return -1;
            }
        }
        String id = user.get("resourceName");
        if(id.startsWith("people/") && id.length()>7) {
            id = id.substring(7);
        }
        def db = context.getDatabase()
        try {
            // Force main wiki database to create the user as global
            context.setDatabase("xwiki")
            // take the first emailAddress if there was none selected for the domain earlier
            if(usersEmailAddress == "" && user.emailAddresses!=null && user.emailAddresses.size()>0) {
                usersEmailAddress = user.emailAddresses[0].value
            }
            def wikiUserList = services.query.xwql("from doc.object(GoogleApps.GoogleAppsAuthClass) as auth where auth.id=:id").bindValue("id", id).execute()
            if ((wikiUserList==null) || (wikiUserList.size()==0))
                wikiUserList = services.query.xwql("from doc.object(XWiki.XWikiUsers) as user where user.email=:email").bindValue("email", usersEmailAddress).execute()

            if ((wikiUserList==null) || (wikiUserList.size()==0)) {
                // user not found.. need to create new user
                xwikiUser = usersEmailAddress.substring(0, usersEmailAddress.indexOf("@"));
                // make sure user is unique
                xwikiUser = xwiki.getUniquePageName("XWiki", xwikiUser);
                // create user
                def parentref = xwiki.getDocumentAsAuthor("Main.UserDirectory").getDocumentReference()
                def randomPassword = RandomStringUtils.randomAlphanumeric(8)
                if(user.names==null || user.names.size()==0) {
                    throw new NullPointerException("Sorry, users without names are not supported.");
                }
                def isCreated = xwiki.getXWiki().createUser(xwikiUser, ["first_name" : user.names[0].givenName, "last_name" : user.names[0].familyName, "email" : usersEmailAddress,  "password" : randomPassword], parentref, null, null, "edit", context.context)
                // Add google apps id to the user
                if (isCreated) {
                    addDebug("Creating user " + xwikiUser);
                    xwikiUser = "XWiki." + xwikiUser
                    def userDoc = xwiki.getDocumentAsAuthor(xwikiUser)
                    userDoc.use("XWiki.XWikiUsers")
                    userDoc.set("first_name", user.names[0].givenName);
                    userDoc.set("last_name",  user.names[0].familyName)
                    userDoc.set("active", 1);
                    if(useAvatar && user.photos && user.photos.size()>0 && user.photos[0].url) {
                        addDebug("Adding avatar " + user.photos[0].url);
                        def u = new URL(user.photos[0].url);
                        def b = u.openStream();

                        String fileName = u.file.substring(u.file.lastIndexOf('/')+1);
                        if(fileName.length()>=254) {
                            int p = fileName.lastIndexOf("."), l = fileName.length();
                            if(l-p<250)
                                fileName = fileName.substring(0, 255-(l-p)) + fileName.substring(p);
                            else // ill-case, extension non-existent or too long
                                fileName = fileName.substring(l-254);
                        }
                        userDoc.addAttachment(fileName, b);
                        userDoc.set("avatar", fileName );
                        b.close()
                    }
                    userDoc.getObject("GoogleApps.GoogleAppsAuthClass", true)
                    userDoc.use("GoogleApps.GoogleAppsAuthClass")
                    userDoc.set("id", id)
                    userDoc.saveWithProgrammingRights("Google Apps login user creation")
                } else {
                    addDebug("User creation failed");
                    return null;
                }
            } else {
                // user found.. we should update it if needed
                xwikiUser = wikiUserList.get(0);
                addDebug("Found user " + xwikiUser);
                boolean changed = false;
                def userDoc = xwiki.getDocumentAsAuthor(xwikiUser);
                if (!userDoc.getObject("XWiki.XWikiUsers")) {
                    addDebug("User found is not a user");
                    return null;
                } else {
                    userDoc.use("XWiki.XWikiUsers")
                    if (userDoc.getValue("email") != usersEmailAddress) {
                        userDoc.set("email", usersEmailAddress)
                        changed = true;
                    }
                    if (userDoc.getValue("first_name") != user.names[0].givenName) {
                        userDoc.set("first_name", user.names[0].givenName)
                        changed = true;
                    }
                    if (userDoc.getValue("last_name") != user.names[0].familyName) {
                        userDoc.set("last_name", user.names[0].familyName)
                        changed = true;
                    }
                    if (userDoc.getValue("active") != 1) {
                        userDoc.set("active", 1);
                        changed = true;
                    }
                    if(useAvatar && user.photos && user.photos.size()>0 && user.photos[0].url) {
                        addDebug("Pulling avatar " + user.photos[0].url);
                        def u = new URL(user.photos[0].url);
                        def bytesFromGoogle = u.getBytes();
                        def attachment = userDoc.get("avatar")==null ? null : userDoc.getAttachment(userDoc.get("avatar"));
                        def fileChanged = attachment==null || attachment.getFilesize()!=bytesFromGoogle.length;
                        if(!fileChanged) {
                            def b = attachment.getContentAsBytes();
                            for(int i=0; i<b.length; i++) if(b[i]!=bytesFromGoogle[i]) {fileChanged = true; break;}
                        }

                        if(fileChanged) {
                            def fileName = u.file.substring(u.file.lastIndexOf('/')+1);
                            addDebug("Avatar changed " + fileName);
                            userDoc.set("avatar", fileName );
                            userDoc.addAttachment(fileName, bytesFromGoogle);
                            changed = true;
                        }
                    }

                    if (userDoc.getObject("GoogleApps.GoogleAppsAuthClass")==null) {
                        userDoc.getObject("GoogleApps.GoogleAppsAuthClass", true)
                        changed = true;
                    }
                    userDoc.use("GoogleApps.GoogleAppsAuthClass")
                    if (userDoc.getValue("id") != id) {
                        userDoc.set("id", id)
                        changed = true;
                    }

                    if (changed) {
                        addDebug("User changed.");
                        userDoc.saveWithProgrammingRights("Google Apps login user updated")
                    } else {
                        addDebug("User unchanged.");
                    }
                }
            }
        } finally {
            // Restore database
            context.setDatabase(db)
        }

        // we need to restore the credentials as the user will now be logged-in
        storeCredentials(xwikiUser, credential);

        // store the validated xwiki user for the authentication module
        request.getSession().setAttribute("googleappslogin", "xwiki:" + xwikiUser);

        return xwikiUser;
    }

    /**
     * Build and return an authorized Drive client service.
     * @return an authorized Drive client service
     * @throws IOException
     */
    def getDriveService() throws IOException {
        Credential credential = authorize();
        return new Drive.Builder(
                HTTP_TRANSPORT, JSON_FACTORY, credential)
                .setApplicationName(APPNAME)
                .build();
    }


    public getDocumentList() {
        def drive = getDriveService();
        def result = drive.files().list().setMaxResults(10).execute();
        return result;
    }

    public importFromGoogleApps(query, nbResults) {
        def drive = getDriveService();
        def req = drive.files().list().setQ(query).setFields("items(id,mimeType,title,exportLinks,selfLink,version,alternateLink)").setMaxResults(nbResults);
        def result = req.execute();
        return result;
    }

    public listDocuments(query, nbResults) {
        def drive = getDriveService();
        def req = drive.files().list().setQ(query).setMaxResults(nbResults);
        def result = req.execute();
        return result;
    }

    public retrieveFileFromGoogle(page, name, id, url) {
        return retrieveFileFromGoogle(getDriveService(), page, name, id, url);
    }

    public retrieveFileFromGoogle(driveService, page, name, id, url) {
        addDebug("Retrieving ${name} to page ${page}: ${id} ${url}" )
        def adoc = xwiki.getDocument(page);
        try {
            String mt = new Tika().detect(name);
            InputStream downloadStream = driveService.files().export(id, mt).executeMediaAsInputStream();
            saveFileToXWiki(driveService, adoc, id, name, downloadStream, true);
            return id;
        } catch (Exception e) {
            addDebug(e.getMessage())
            e.printStackTrace();
        }
    }

    public saveFileToXWiki(driveService, adoc, id, name, data, redirect) {
        def attachment = adoc.addAttachment(name, data);

        // ready to save now
        adoc.getDoc().saveAttachmentContent(attachment.getAttachment(), context.getContext());

        def user = driveService.about().get().execute().getUser().emailAddress;
        def docData = driveService.files().get(id).execute();
        def embedLink = docData.embedLink;
        if (embedLink==null)
            embedLink = docData.alternateLink;

        adoc.save("Updated Attachment From Google Apps");

        def object = adoc.getObject("GoogleApps.SynchronizedDocumentClass", "fileName", name.toString(), false);
        if (object==null) {
            object = adoc.newObject("GoogleApps.SynchronizedDocumentClass")
        }
        adoc.use(object);
        adoc.set("id", id)
        adoc.set("fileName", name)
        if (request.url)
            adoc.set("exportLink", request.url)
        adoc.set("version", docData.version.toString())
        adoc.set("editLink", docData.alternateLink)
        adoc.set("embedLink", embedLink)
        if (adoc.getValue("user")=="")
            adoc.set("user", user)
        adoc.save("Updated Google Apps Document metadata")
        addDebug("Document ${name} has been saved to XWiki")

        if (redirect) {
            def rurl = adoc.getURL("view", "#Attachments")
            context.response.sendRedirect(rurl);
        }
    }

    public getGoogleDocument(pageName, fileName) {
        def adoc = xwiki.getDocument(pageName);
        def object = adoc.getObject("GoogleApps.SynchronizedDocumentClass", "fileName", fileName, false);
        if (object==null) {
            return null;
        } else {
            adoc.use(object);
            return [ "id" : adoc.getValue("id"), "editLink" : adoc.getValue("editLink"), "exportLink" : adoc.getValue("exportLink")]
        }
    }

    public getExportLink(docName, elink) {
        def index = elink.indexOf("exportFormat=") + 13;
        def extension = elink.substring(index);
        addDebug("Found extension: " + extension);
        def newDocName = docName.replaceAll("\\.(doc|docx|odt|xls|xlsx|ods|pptx|pdf|svg|png|jpeg|pdf|)\$","")
        newDocName += "." + extension;
        addDebug("Found extension: " + extension);
        addDebug("Found new DocName: " + newDocName);
        return [ "type" : extension, "newDocName" : newDocName];
    }

    Set prohibitedFormats = new HashSet();

    public boolean canSyncFile(fileName) {
        def p = fileName.lastIndexOf(".");
        if(p==-1 || p == fileName.length()-1) return true;
        fileName = fileName.substring(p+1).toLowerCase();
        if(prohibitedFormats.size()==0) {
            prohibitedFormats.add("doc");
            prohibitedFormats.add("xls");
            prohibitedFormats.add("ppt");
        }
        return !prohibitedFormats.contains(fileName);
    }

    public getFileDisplayInfo(mimeType, docName) {
        def newDocName;
        def availableTypes;
        if (mimeType.endsWith("document")) {
            newDocName = docName.replaceAll("\\.doc\$","").replaceAll("\\.docx\$","").replaceAll("\\.odt\$","");
            availableTypes = [ "odt", "doc", "pdf" ];
        } else if (mimeType.endsWith("spreadsheet")) {
            newDocName = docName.replaceAll("\\.xls\$","").replaceAll("\\.xlsx\$","").replaceAll("\\.ods\$","");
            availableTypes = [ "ods", "xls", "xlsx", "pdf" ];
        } else if (mimeType.endsWith("presentation")) {
            newDocName = docName.replaceAll("\\.ppt\$","").replaceAll("\\.pptx\$","").replaceAll("\\.odp\$","");
            availableTypes = [ "pptx", "pdf", "svg", "png", "jpeg" ];
        } else if (mimeType.endsWith("pdf")) {
            newDocName = docName.replaceAll("\\.pdf\$","").replaceAll("\\.pdf\$","").replaceAll("\\.pdf\$","");
            availableTypes = [ "pdf" ];
        } else if (mimeType.endsWith("drawing")) {
            newDocName = docName.replaceAll("\\.svg\$","");
            availableTypes = [ "svg", "png", "jpeg", "pdf" ];
        } else if (mimeType.endsWith("folder")) {
            newDocName = docName;
            availableTypes = [ "folder" ];
        } else {
            newDocName = docName;
            availableTypes = [ "" ];
        }
        return [ docName : newDocName, availableTypes : availableTypes ]
    }

    public findExportLink(name, entry) {
        def exportLink = "";
        def lastLink = ""
        for (elink in entry.exportLinks) {
            addDebug("Checking link: " + elink);
            lastLink = elink.value;
            def index = lastLink.indexOf("exportFormat=") + 13;
            def extension = lastLink.substring(index);
            if (name.endsWith("." + extension))
                return lastLink;
        }
        def index = lastLink.indexOf("exportFormat=") + 13;
        exportLink = lastLink.substring(0, index);
        if (name.endsWith(".xls"))
            exportLink += "xlsx";
        else {
            exportLink += name.substring(name.lastIndexOf(".") + 1);
        }
        return exportLink;
    }

    public saveAttachmentToGoogle(page, name) {
        addDebug("Starting saving attachment ${name} from page ${page}")
        def adoc = xwiki.getDocument(page);
        def attach = adoc.getAttachment(name);
        def ctype = attach.getMimeType();

        def file = new com.google.api.services.drive.model.File();
        file.setTitle(name);
        file.setOriginalFilename(name);
        def content = new ByteArrayContent(ctype, attach.getContentAsBytes());
        def drive = getDriveService();
        def user = drive.about().get().execute().getUser().emailAddress;
        def insert = drive.files().insert(file, content);
        insert.setConvert(true);
        def docData = insert.execute();
        if (docData) {
            addDebug("File inserted " + docData);
            def embedLink = docData.embedLink;
            if (embedLink==null)
                embedLink = docData.alternateLink;

            def object = adoc.newObject("GoogleApps.SynchronizedDocumentClass");
            adoc.use(object);
            adoc.set("id", "${docData.id}".toString())
            adoc.set("fileName", name)
            adoc.set("exportLink", findExportLink(name, docData).toString())
            adoc.set("version", docData.version.toString())
            adoc.set("editLink", docData.alternateLink)
            adoc.set("embedLink", embedLink)
            adoc.set("user", user)
            adoc.save("Updated Google Apps Document metadata")
            return [ "id" : adoc.getValue("id"), "editLink" : adoc.getValue("editLink"), "exportLink" : adoc.getValue("exportLink")]

        } else {
            addDebug("File insert failed");
            return null;
        }
    }

    public getGoogleUser() {
        return googleUser;
    }

    /**
     * checks that the xwiki.cfg adjustments are in (note: only works from XWiki 11)
     * @return true if found and equal, false otherwise
     */
    public missesAuthenticationConfig(services) {
        /*
            xwiki.authentication.authclass=com.xpn.xwiki.user.impl.xwiki.GroovyAuthServiceImpl
            xwiki.authentication.groovy.pagename=xwiki:GoogleApps.AuthService
         */
        def xwikicfg = services.component.getInstance(
          Class.forName("org.xwiki.configuration.ConfigurationSource"), "xwikicfg");
        if(xwikicfg==null) {
            return false;
        }
        return !(
          xwikicfg.getProperty("xwiki.authentication.authclass")=="com.xpn.xwiki.user.impl.xwiki.GroovyAuthServiceImpl" &&
          xwikicfg.getProperty("xwiki.authentication.groovy.pagename")=="xwiki:GoogleApps.AuthService" );
    }

}
