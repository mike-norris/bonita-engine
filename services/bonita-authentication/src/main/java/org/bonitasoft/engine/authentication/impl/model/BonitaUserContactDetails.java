package org.bonitasoft.engine.authentication.impl.model;

public class BonitaUserContactDetails {
    String id;
    String email;

    public BonitaUserContactDetails(String id, String email) {
        this.id = id;
        this.email = email;
    }

    public BonitaUserContactDetails() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
