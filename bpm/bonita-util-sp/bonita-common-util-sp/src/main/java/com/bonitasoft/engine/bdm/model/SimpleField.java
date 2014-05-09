/*******************************************************************************
 * Copyright (C) 2014 Bonitasoft S.A.
 * Bonitasoft is a trademark of Bonitasoft SA.
 * This software file is BONITASOFT CONFIDENTIAL. Not For Distribution.
 * For commercial licensing information, contact:
 * Bonitasoft, 32 rue Gustave Eiffel 38000 Grenoble
 * or Bonitasoft US, 51 Federal Street, Suite 305, San Francisco, CA 94107
 *******************************************************************************/
package com.bonitasoft.engine.bdm.model;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlType;

import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;

/**
 * @author Matthieu Chaffotte
 */
@XmlType(name = "simpleField")
public class SimpleField extends Field {

    @XmlAttribute(required = true)
    private FieldType type;

    @XmlAttribute
    private Integer length;

    public FieldType getType() {
        return type;
    }

    public void setType(final FieldType type) {
        this.type = type;
    }

    public Integer getLength() {
        return length;
    }

    public void setLength(final Integer length) {
        this.length = length;
    }

    @Override
    public int hashCode() {
        return new HashCodeBuilder(17, 37).appendSuper(super.hashCode()).append(length).append(type).toHashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        if (obj instanceof SimpleField) {
            final SimpleField other = (SimpleField) obj;
            return new EqualsBuilder()
                    .appendSuper(super.equals(obj))
                    .append(length, other.length)
                    .append(type, other.type)
                    .isEquals();
        } else {
            return false;
        }
    }

}
