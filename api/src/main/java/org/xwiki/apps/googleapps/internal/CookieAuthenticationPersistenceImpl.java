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
package org.xwiki.apps.googleapps.internal;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.servlet.http.Cookie;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import org.slf4j.Logger;
import org.xwiki.apps.googleapps.CookieAuthenticationPersistence;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.annotation.InstantiationStrategy;
import org.xwiki.component.descriptor.ComponentInstantiationStrategy;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.stability.Unstable;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * Tools to help storing and retrieving enriched information within cookies such as the
 * linked Google user profile.
 *
 * Copied code from xwiki-authenticator-trusted
 * https://github.com/xwiki-contrib/xwiki-authenticator-trusted/edit/master\
 *   /xwiki-authenticator-trusted-api/src/main/java/org/xwiki/contrib/authentication\
 *   /internal/CookieAuthenticationPersistenceStore.java.
 * @version $Id$
 * @since 3.0
 */
@Component
@InstantiationStrategy(ComponentInstantiationStrategy.PER_LOOKUP)
public class CookieAuthenticationPersistenceImpl implements CookieAuthenticationPersistence
{
    private static final String AUTHENTICATION_CONFIG_PREFIX = "xwiki.authentication";

    private static final String COOKIE_PREFIX_PROPERTY = AUTHENTICATION_CONFIG_PREFIX + ".cookieprefix";
    private static final String COOKIE_PATH_PROPERTY =  AUTHENTICATION_CONFIG_PREFIX + ".cookiepath";
    private static final String COOKIE_DOMAINS_PROPERTY = AUTHENTICATION_CONFIG_PREFIX + ".cookiedomains";
    private static final String ENCRYPTION_KEY_PROPERTY = AUTHENTICATION_CONFIG_PREFIX + ".encryptionKey";

    private static final String CIPHER_ALGORITHM = "TripleDES";

    private static final String AUTHENTICATION_COOKIE = "XWIKITRUSTEDAUTH";

    /**
     * The string used to prefix cookie domain to conform to RFC 2109.
     */
    private static final String COOKIE_DOT_PFX = ".";

    private static final String EQUAL_SIGN = "=";
    private static final String UNDERSCORE = "_";

    @Inject
    private Logger logger;

    private XWikiContext context;

    @Inject
    private ComponentManager componentManager;

    private String cookiePfx;
    private String cookiePath;
    private String[] cookieDomains;
    private long cookieMaxAge;
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;


    /**
     * Initialize the tool.
     * @param context XWiki Context
     * @param cookieMaxAge Time To Live of the created cookies in scd
     * @throws XWikiException in case of trouble
     * @since 3.0
     */
    @Unstable
    public void initialize(XWikiContext context, long cookieMaxAge) throws XWikiException
    {
        this.context = context;
        cookiePfx = this.context.getWiki().Param(COOKIE_PREFIX_PROPERTY, "");
        cookiePath = this.context.getWiki().Param(COOKIE_PATH_PROPERTY, "/");

        String[] cdlist = StringUtils.split(this.context.getWiki().Param(COOKIE_DOMAINS_PROPERTY), ',');
        if (cdlist != null && cdlist.length > 0) {
            this.cookieDomains = new String[cdlist.length];
            for (int i = 0; i < cdlist.length; ++i) {
                cookieDomains[i] = conformCookieDomain(cdlist[i]);
            }
        } else {
            cookieDomains = null;
        }

        this.cookieMaxAge = cookieMaxAge;

        try {
            encryptionCipher = getCipher(true);
            decryptionCipher = getCipher(false);
        } catch (Exception e) {
            throw new XWikiException("Unable to initialize ciphers", e);
        }
    }

    /**
     * Erases the information stored.
     * @since 3.0
     */
    @Unstable
    public void clear()
    {
        cookieMaxAge = 0;
        this.store(this.retrieve());
    }

    /**
     * Store the user-information within the cookie.
     * @param userUid the user-name (without xwiki. prefix)
     * @since 3.0
     */
    @Unstable
    public void store(String userUid)
    {
        Cookie cookie = new Cookie(cookiePfx + AUTHENTICATION_COOKIE, encryptText(userUid));
        cookie.setMaxAge((int) cookieMaxAge);
        cookie.setPath(cookiePath);
        String cookieDomain = getCookieDomain();
        if (cookieDomain != null) {
            cookie.setDomain(cookieDomain);
        }
        if (context.getRequest().isSecure()) {
            cookie.setSecure(true);
        }
        context.getResponse().addCookie(cookie);
    }

    /**
     * Retrieving the login read from the cookie.
     *
     * @return the login name found, or null.
     * @since 3.0
     */
    @Unstable
    public String retrieve()
    {
        logger.info("retrieve cookie " + cookiePfx + AUTHENTICATION_COOKIE);
        String cookie = getCookieValue(cookiePfx + AUTHENTICATION_COOKIE);
        if (cookie != null) {
            return decryptText(cookie);
        }
        return null;
    }

    private Cipher getCipher(boolean encrypt)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException
    {
        Cipher cipher = null;
        String secretKey = context.getWiki().Param(ENCRYPTION_KEY_PROPERTY);
        if (secretKey != null) {
            secretKey = secretKey.substring(0, 24);
            SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(), CIPHER_ALGORITHM);
            cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key);
        }
        return cipher;
    }

    private String encryptText(String text)
    {
        try {
            logger.info("text to encrypt : " + text);
            String encryptedText = new String(Base64.encodeBase64(
                    encryptionCipher.doFinal(text.getBytes()))).replaceAll(EQUAL_SIGN, UNDERSCORE);
            logger.info("encrypted text : " + encryptedText);
            return encryptedText;
        } catch (Exception e) {
            logger.error("Failed to encrypt text", e);
        }
        return null;
    }

    private String decryptText(String text)
    {
        try {
            logger.info("text to decrypt : " + text);
            String decryptedText = new String(decryptionCipher.doFinal(
                    Base64.decodeBase64(text.replaceAll(UNDERSCORE, EQUAL_SIGN).getBytes(
                    StandardCharsets.ISO_8859_1))));
            logger.info("decrypted text : " + decryptedText);
            return decryptedText;
        } catch (Exception e) {
            logger.error("Failed to decrypt text", e);
        }
        return null;
    }

    /**
     * Retrieve given cookie null-safe.
     * @param cookieName name of the cookie
     * @return the cookie
     * @since 3.0
     */
    private String getCookieValue(String cookieName)
    {
        if (context.getRequest() != null) {
            Cookie cookie = context.getRequest().getCookie(cookieName);
            if (cookie != null) {
                logger.info("cookie : " + cookie);
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Compute the actual domain the cookie is supposed to be set for. Search through the list of generalized domains
     * for a partial match. If no match is found, then no specific domain is used, which means that the cookie will be
     * valid only for the requested host.
     *
     * @return The configured domain generalization that matches the request, or null if no match is found.
     * @since 3.0
     */
    private String getCookieDomain()
    {
        String cookieDomain = null;
        if (this.cookieDomains != null) {
            // Conform the server name like we conform cookie domain by prefixing with a dot.
            // This will ensure both localhost.localdomain and any.localhost.localdomain will match
            // the same cookie domain.
            String servername = conformCookieDomain(context.getRequest().getServerName());
            for (String domain : this.cookieDomains) {
                if (servername.endsWith(domain)) {
                    cookieDomain = domain;
                    break;
                }
            }
        }
        logger.debug("Cookie domain is:" + cookieDomain);
        return cookieDomain;
    }

    /**
     * Ensure cookie domains are prefixed with a dot to conform to RFC 2109.
     *
     * @param domain a cookie domain.
     * @return a conform cookie domain.
     * @since 3.0
     */
    private String conformCookieDomain(String domain)
    {
        if (domain != null && !domain.startsWith(COOKIE_DOT_PFX)) {
            return COOKIE_DOT_PFX.concat(domain);
        } else {
            return domain;
        }
    }
}
