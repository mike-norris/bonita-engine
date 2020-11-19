package org.bonitasoft.engine.authentication.impl.model;

public class UserIdentificationResponse {
    String copyright;
    String user_id;
    String user_name;
    String session_id;
    String conf;
    String is_technical_user;
    String version;
    String error;
    String ipAddress;

    public UserIdentificationResponse() {
    }

    public UserIdentificationResponse(String userId, String userName) {
        this.user_id = userId;
        this.user_name = userName;
    }

    public String getCopyright() {
        return copyright;
    }

    public void setCopyright(String copyright) {
        this.copyright = copyright;
    }

    public String getUser_id() {
        return user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }

    public String getUser_name() {
        return user_name;
    }

    public void setUser_name(String user_name) {
        this.user_name = user_name;
    }

    public String getSession_id() {
        return session_id;
    }

    public void setSession_id(String session_id) {
        this.session_id = session_id;
    }

    public String getConf() {
        return conf;
    }

    public void setConf(String conf) {
        this.conf = conf;
    }

    public String getIs_technical_user() {
        return is_technical_user;
    }

    public void setIs_technical_user(String is_technical_user) {
        this.is_technical_user = is_technical_user;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
