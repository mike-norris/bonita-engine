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
package org.bonitasoft.engine.data.instance.model.archive;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.bonitasoft.engine.data.instance.model.SDataInstance;
import org.hibernate.annotations.Type;

@Data
@NoArgsConstructor
@EqualsAndHashCode(callSuper = true)
@SuperBuilder
@Entity
@DiscriminatorValue("SADateDataInstanceImpl")
public class SADateDataInstance extends SADataInstance {

    @Column(name = "longValue")
    @Type(type = "org.bonitasoft.engine.persistence.DateStoredAsLongUserType")
    private Date value;

    public SADateDataInstance(final SDataInstance sDataInstance) {
        super(sDataInstance);
        value = (Date) sDataInstance.getValue();
    }

    @Override
    public Date getValue() {
        return value;
    }

    @Override
    public void setValue(final Serializable value) {
        this.value = (Date) value;
    }

}
