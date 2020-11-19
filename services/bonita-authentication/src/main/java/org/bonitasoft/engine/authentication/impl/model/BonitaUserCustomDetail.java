package org.bonitasoft.engine.authentication.impl.model;

public class BonitaUserCustomDetail {
    String userId;
    String value;
    BonitaUserCustomDetailDefinition definitionId;

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public BonitaUserCustomDetailDefinition getDefinitionId() {
        return definitionId;
    }

    public void setDefinitionId(BonitaUserCustomDetailDefinition definitionId) {
        this.definitionId = definitionId;
    }
}
