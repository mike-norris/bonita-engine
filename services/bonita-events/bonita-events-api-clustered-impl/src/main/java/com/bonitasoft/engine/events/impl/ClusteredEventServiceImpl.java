/**
 * Copyright (C) 2011-2013 BonitaSoft S.A.
 * BonitaSoft, 32 rue Gustave Eiffel - 38000 Grenoble
 * This library is free software; you can redistribute it and/or modify it under the terms
 * of the GNU Lesser General Public License as published by the Free Software Foundation
 * version 2.1 of the License.
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License along with this
 * program; if not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
 * Floor, Boston, MA 02110-1301, USA.
 **/
package com.bonitasoft.engine.events.impl;

import java.util.Map;

import org.bonitasoft.engine.events.model.HandlerRegistrationException;
import org.bonitasoft.engine.events.model.SEvent;
import org.bonitasoft.engine.events.model.SHandler;
import org.bonitasoft.engine.events.model.builders.SEventBuilders;
import org.bonitasoft.engine.log.technical.TechnicalLoggerService;

import com.hazelcast.core.HazelcastInstance;

public class ClusteredEventServiceImpl extends ConfigurableEventServiceImpl {

    public ClusteredEventServiceImpl(final SEventBuilders eventBuilders, final Map<String, SHandler<SEvent>> handlers, final TechnicalLoggerService logger, final HazelcastInstance hazelcastInstance) throws HandlerRegistrationException {
        this("PLATFORM", eventBuilders, handlers, logger, hazelcastInstance);
    }

    public ClusteredEventServiceImpl(final SEventBuilders eventBuilders, final Map<String, SHandler<SEvent>> handlers, final TechnicalLoggerService logger, final HazelcastInstance hazelcastInstance, final long tenantId) throws HandlerRegistrationException {
        this("TENANT@" + tenantId, eventBuilders, handlers, logger, hazelcastInstance);
    }

    private ClusteredEventServiceImpl(final String eventServiceHandlerMapNameSuffix, final SEventBuilders eventBuilders, final Map<String, SHandler<SEvent>> handlers, final TechnicalLoggerService logger, final HazelcastInstance hazelcastInstance) throws HandlerRegistrationException {
        super(eventBuilders, handlers, logger);

        // Create a Map that is shared across the cluster.
        registeredHandlers = hazelcastInstance.getMap("EVENT_SERVICE_HANDLERS-" + eventServiceHandlerMapNameSuffix);

        // register the handlers with their associated event type
        for (final Map.Entry<String, SHandler<SEvent>> entry : handlers.entrySet()) {
            addHandler(entry.getKey(), entry.getValue());
        }
    }

}
