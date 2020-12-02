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

import java.util.Arrays;
import java.util.List;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.xwiki.bridge.event.ApplicationReadyEvent;
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.EventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Registered object to listen to document changes.
 *
 * @version $Id$
 * @since 3.0
 */
@Component(roles = GoogleAppsEventListener.class)
@Singleton
public class GoogleAppsEventListener implements EventListener
{
    @Inject
    private GoogleAppsXWikiObjects gaXWikiObjects;

    /**
     * The name of the event listener.
     *
     * @return googleapps.scriptservice.
     */
    @Override
    public String getName()
    {
        return "googleapps.scriptservice";
    }

    /**
     * The event-types listened to.
     *
     * @return ApplicationReadyEvent and DocumentUpdatedEvent
     */
    @Override
    public List<Event> getEvents()
    {
        return Arrays.asList(new ApplicationReadyEvent(), new DocumentUpdatedEvent());
    }

    /**
     * Triggers a configuration reload (if the configuration is changed or the app is started) or an initialization (if
     * the app is started).
     *
     * @param event  The event listened to.
     * @param source The object sending the event.
     * @param data   Data about the event.
     */
    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        boolean applicationStarted = false;
        boolean configChanged = false;
        if (event instanceof ApplicationReadyEvent) {
            applicationStarted = true;
        }
        if (event instanceof DocumentUpdatedEvent) {
            XWikiDocument document = (XWikiDocument) source;
            DocumentReference configDocRef = gaXWikiObjects.getConfigDocRef();
            if (document != null && document.getDocumentReference().equals(configDocRef)) {
                configChanged = true;
            }
        }

        if (configChanged || applicationStarted) {
            gaXWikiObjects.restart();
        }
    }
}
