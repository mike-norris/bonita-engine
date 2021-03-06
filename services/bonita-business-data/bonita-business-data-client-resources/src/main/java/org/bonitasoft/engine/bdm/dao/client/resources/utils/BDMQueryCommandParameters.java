/**
 * Copyright (C) 2019 Bonitasoft S.A.
 * Bonitasoft, 32 rue Gustave Eiffel - 38000 Grenoble
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
package org.bonitasoft.engine.bdm.dao.client.resources.utils;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

import org.bonitasoft.engine.bdm.model.field.Field;

public class BDMQueryCommandParameters {

    public static Map<String, Serializable> createCommandParameters(final EntityGetter getter,
            final long persistenceId) {
        final Map<String, Serializable> commandParameters = new HashMap<String, Serializable>();
        commandParameters.put("queryName", getter.getAssociatedNamedQuery());
        commandParameters.put("returnType", getter.getReturnTypeClassName());
        commandParameters.put("returnsList", getter.returnsList());
        commandParameters.put("startIndex", 0);
        commandParameters.put("maxResults", Integer.MAX_VALUE);
        final Map<String, Serializable> queryParameters = new HashMap<String, Serializable>();
        queryParameters.put(Field.PERSISTENCE_ID, persistenceId);
        commandParameters.put("queryParameters", (Serializable) queryParameters);
        return commandParameters;
    }
}
