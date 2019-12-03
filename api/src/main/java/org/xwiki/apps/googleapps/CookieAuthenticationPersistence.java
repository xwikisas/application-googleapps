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
package org.xwiki.apps.googleapps;

import org.xwiki.component.annotation.Role;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;

/**
 * Set of methods for the management of the cookies.
 *
 * @since 3.0
 * @version $Id$
 */
@Role
public interface CookieAuthenticationPersistence
{
    /**
     * Stores the user-id in an encryted fashion in the cookie.
     *
     * @param userId the string to store
     * @since 3.0
     */
    void store(String userId);

    /**
     * Reads the user-id from the cookie.
     *
     * @return the decrypted user-id
     * @since 3.0
     */
    String retrieve();

    /**
     * Removes stored information from the cookie.
     *
     * @since 3.0
     */
    void clear();

    /**
     * Initialize with the local parameters.
     *
     * @param context Context of the request (e.g. for cookies)
     * @param cookieMaxAge Configure maximum age of the cookie.
     * @throws XWikiException if anything goes wrong
     * @since 3.0
     */
    void initialize(XWikiContext context, long cookieMaxAge) throws XWikiException;

}
