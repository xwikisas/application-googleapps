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

import java.io.IOException;

import org.xwiki.stability.Unstable;

import com.xpn.xwiki.XWikiException;

/**
 * Generic class to denote an exception condition within the GoogleApps code. Wraps XWikiException and IOException.
 *
 * @version $Id$
 * @since 3.0
 */
@Unstable
public class GoogleAppsException extends RuntimeException
{
    private static final long serialVersionUID = 3000;

    /**
     * @param msg     Message to denote the error for programmers.
     * @param wrapped Exception that has caused this one.
     * @since 3.0
     */
    public GoogleAppsException(String msg, Exception wrapped)
    {
        super(msg, wrapped);
    }

    /**
     * @param msg Message to denote the error for programmers.
     * @since 3.0
     */
    public GoogleAppsException(String msg)
    {
        super(msg);
    }

    /**
     * @param wrapped Exception that has caused this one.
     * @since 3.0
     */
    public GoogleAppsException(Exception wrapped)
    {
        super(wrapped);
    }

    /**
     * @return true if the wrapped exception of XWiki origin.
     * @since 3.0
     */
    public boolean isWikiException()
    {
        return getCause() instanceof XWikiException;
    }

    /**
     * @return true if the wrapped exception of Google origin (for now: any IO-related exception).
     * @since 3.0
     */
    public boolean isGoogleException()
    {
        return getCause() instanceof IOException;
    }
}
