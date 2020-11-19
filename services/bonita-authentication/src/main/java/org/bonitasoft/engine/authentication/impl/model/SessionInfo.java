package org.bonitasoft.engine.authentication.impl.model;

public class SessionInfo {

    String sessionToken;
    String sessionId;

    public SessionInfo(String sessionToken, String sessionId) {
        this.sessionToken = sessionToken;
        this.sessionId = sessionId;
    }

    public SessionInfo() {
    }

    public String getSessionToken() {
        return sessionToken;
    }

    public void setSessionToken(String sessionToken) {
        this.sessionToken = sessionToken;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
}
