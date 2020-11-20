/**
 * Copyright (C) 2015 BonitaSoft S.A.
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
package org.bonitasoft.engine.authentication.impl;

import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.bonitasoft.engine.api.APIAccessor;
import org.bonitasoft.engine.api.APIClient;
import org.bonitasoft.engine.api.IdentityAPI;
import org.bonitasoft.engine.api.LoginAPI;
import org.bonitasoft.engine.authentication.impl.model.*;
import org.bonitasoft.engine.exception.AlreadyExistsException;
import org.bonitasoft.engine.identity.*;
import org.bonitasoft.engine.session.APISession;
import org.bonitasoft.engine.authentication.AuthenticationConstants;
import org.bonitasoft.engine.authentication.GenericAuthenticationService;
import org.bonitasoft.engine.commons.LogUtil;
import org.bonitasoft.engine.identity.model.SUser;
import org.bonitasoft.engine.log.technical.TechnicalLogSeverity;
import org.bonitasoft.engine.log.technical.TechnicalLoggerService;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.CommunicationException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.security.auth.login.AccountException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

/**
 * @author Elias Ricken de Medeiros
 * @author Matthieu Chaffotte
 * @author Hongwen Zang
 * @author Julien Reboul
 * @author Celine Souchet
 * @author Ben Inkster
 */
public class AuthenticationServiceImpl implements GenericAuthenticationService {

    private final IdentityService identityService;
    private final TechnicalLoggerService logger;

    private static final String CONTEXT_FACTORY_CLASS = "com.sun.jndi.ldap.LdapCtxFactory";
    private String ldapServerUrls[] = {"ldaps://ldap.mydcblox.com:636"};
    private int lastLdapUrlIndex;
    private final String domainName = "MYDCBLOX.COM";
    private Attributes attrs;
    private static final ObjectMapper mapper = new ObjectMapper();
    private IdentityAPI identityAPI;
    private LoginAPI loginAPI;

    public AuthenticationServiceImpl(final IdentityService identityService, final TechnicalLoggerService logger) {
        System.out.println("AuthenticationServiceImpl:::JAR CONSTRUCTED!!!");
        this.identityService = identityService;
        this.logger = logger;

        lastLdapUrlIndex = 0;
    }

    /**
     * @see org.bonitasoft.engine.authentication.GenericAuthenticationService#checkUserCredentials(java.util.Map)
     */
    @Override
    public String checkUserCredentials(Map<String, Serializable> credentials) {
        System.out.println("checkUserCredentials(Map<String, Serializable> credentials) Starts!!!!!!!!!!!!!!!!!!");
        final String methodName = "checkUserCredentials";
        final String password = String.valueOf(credentials.get(AuthenticationConstants.BASIC_PASSWORD));
        final String userName = String.valueOf(credentials.get(AuthenticationConstants.BASIC_USERNAME));

        try {

            if (logger.isLoggable(this.getClass(), TechnicalLogSeverity.TRACE)) {
                logger.log(this.getClass(), TechnicalLogSeverity.TRACE, LogUtil.getLogBeforeMethod(this.getClass(), methodName));
            }

            // Check the AD credentials
            if (this.authenticate(userName,password)) {
                try {
                    System.out.println("Going through Attributes");
                    NamingEnumeration<String> attribsIDs = this.attrs.getIDs();
                    while (attribsIDs.hasMore()) {
                        String attrID = attribsIDs.next();
                        System.out.println("Attribute from checking AD Credentials"+this.attrs.get(attrID));
                    }

                    System.out.println("Getting GUID");
                    byte[] guidArray = (byte[]) attrs.get("objectGUID").get();
                    String guid = convertToDashedString(guidArray);
                    String email = attrs.get("mail").get().toString();

                    // check if a user exists in bonita
                    final SUser user;
                    try {
                        System.out.println("Trying to get user from identity service. User:"+userName);
                        user = identityService.getUserByUserName(userName);
                    } catch (final SUserNotFoundException sunfe) {
                        System.out.println("User:"+userName+" does not exist. Creating user.");
                        // if user doesn't exist, we need to create one (if they do exist in AD)
                        if (logger.isLoggable(this.getClass(), TechnicalLogSeverity.TRACE)) {
                            logger.log(this.getClass(), TechnicalLogSeverity.TRACE, LogUtil.getLogAfterMethod(this.getClass(), methodName));
                        }

                        // fetch details from AD
                        try {
                            System.out.println("Sorting attributes for user:"+userName);
                            while (attribsIDs.hasMore()) {
                                String attrID = attribsIDs.next();
                                System.out.println("Attributefrom AD:"+ this.attrs.get(attrID) +"with attrid:"+attrID);
                            }
                            // create a new user in Bonita
                            String userPass = password;
                            String firstName = attrs.get("givenName").get().toString();
                            String lastName = attrs.get("sn").get().toString();

                            System.out.println("Creating user:"+userName);
                            UserCreateRequest userCreateRequest = new UserCreateRequest();
                            userCreateRequest.setUserName(userName);
                            userCreateRequest.setFirstname(firstName);
                            userCreateRequest.setLastname(lastName);
                            userCreateRequest.setEnabled("true");
                            userCreateRequest.setPassword(userPass+"_bonitapass");
                            userCreateRequest.setPassword_confirm(userPass+"_bonitapass");

                            User userDetails = this.createUser(userCreateRequest);
                            if (null == userDetails) {
                                return "";
                            }
                            System.out.println("Posted user:"+userName+" to bonita");
                            System.out.println("CREATE USER RESONPONSE:"+userDetails);

                            String userID = "";
                            System.out.println("Checking userid:"+userDetails.getId());
                            if (userDetails.getId() > 0) {
                                userID = String.valueOf(userDetails.getId());
                                System.out.println("User id after posting userid:"+userID);

                                Membership membership = new Membership();
                                membership.setGroup_id("101");
                                membership.setRole_id("1");
                                membership.setUser_id(userID);

                                try {
                                    System.out.println("Posting new membership with userid:" + userID);
                                    this.addMembership(membership);
                                    System.out.println("PostedNewMembership for userid:" + userID);
                                } catch (Exception e) {
                                    System.out.println(e.getMessage());
                                }
                                BonitaUserContactDetails bonitaUserContactDetails = new BonitaUserContactDetails();
                                bonitaUserContactDetails.setEmail(email);
                                bonitaUserContactDetails.setId(userID);

                                try {
                                    System.out.println("Posting professional details email:" + email);
                                    this.createProfessionalContactDetails(bonitaUserContactDetails);
                                    System.out.println("Response status from posting email:" + email + " for user name:" + userDetails.getUserName());
                                } catch (Exception e) {
                                    System.out.println("Creating professional contact detailed failed. Will attempt update instead.");
                                    e.printStackTrace();
                                    System.out.println("Updating professional details email:" + email);
                                    this.updateProfessionalContactDetails(bonitaUserContactDetails);
                                    System.out.println("Response status from updating email:" + email + " for user name:" + userDetails.getUserName());
                                }

                                System.out.println("Posting guid:"+guid);
                                this.createGUID("{\"value\":\"" + guid + "\"}", userID);
                                System.out.println("Putting the guid:"+guid);

                            } else {
                                System.out.println("Error setting up new member");
                            }
                            TimeUnit.SECONDS.sleep(2);

                            return userName;

                        } catch (Throwable throwable) {
                            throwable.printStackTrace();
                            return userName;
                        }
                    }


                    //Set the email
                    BonitaUserContactDetails bonitaUserContactDetails = new BonitaUserContactDetails();
                    bonitaUserContactDetails.setEmail(email);
                    bonitaUserContactDetails.setId(user.getId()+"");

                    System.out.println("Posting professional details email:"+email+" for already created user");
                    this.updateProfessionalContactDetails(bonitaUserContactDetails);
                    System.out.println("Response status from posting email:"+email+" for user name:"+user.getUserName());

                    System.out.println("Posting guid:"+guid+" for already created user");
                    this.createGUID(guid, user.getId()+"");
                    System.out.println("Putting the guid:"+guid);

                } catch (Throwable throwable) {
                    throwable.printStackTrace();
                    return userName;
                }

                if (logger.isLoggable(this.getClass(), TechnicalLogSeverity.TRACE)) {
                    logger.log(this.getClass(), TechnicalLogSeverity.TRACE, LogUtil.getLogAfterMethod(this.getClass(), methodName));
                }
                return userName;
            }

            // user exists, but password incorrect
            if (logger.isLoggable(this.getClass(), TechnicalLogSeverity.TRACE)) {
                logger.log(this.getClass(), TechnicalLogSeverity.TRACE, LogUtil.getLogAfterMethod(this.getClass(), methodName));
            }

        } catch (LoginException e) {
            // Login details throw exception
            if (logger.isLoggable(this.getClass(), TechnicalLogSeverity.TRACE)) {
                logger.log(this.getClass(), TechnicalLogSeverity.TRACE, LogUtil.getLogOnExceptionMethod(this.getClass(), methodName, e));
            }
        }
        System.out.println("AUTHENTICATION FAILURE RETURNING NULL");
        return null;
    }

    public static String convertToDashedString(byte[] objectGUID) {
        StringBuilder displayStr = new StringBuilder();

        displayStr.append(prefixZeros((int) objectGUID[3] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[2] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[1] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[0] & 0xFF));
        displayStr.append("-");
        displayStr.append(prefixZeros((int) objectGUID[5] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[4] & 0xFF));
        displayStr.append("-");
        displayStr.append(prefixZeros((int) objectGUID[7] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[6] & 0xFF));
        displayStr.append("-");
        displayStr.append(prefixZeros((int) objectGUID[8] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[9] & 0xFF));
        displayStr.append("-");
        displayStr.append(prefixZeros((int) objectGUID[10] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[11] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[12] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[13] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[14] & 0xFF));
        displayStr.append(prefixZeros((int) objectGUID[15] & 0xFF));

        return displayStr.toString();
    }

    public boolean authenticate(String username, String password) throws LoginException {
        System.out.println("authenticate(String username, String password) Starts!!!!!!!!!!!!!!!!!!");
        if (ldapServerUrls == null || ldapServerUrls.length == 0) {
            System.out.println("Unable to find ldap servers");
            throw new AccountException("Unable to find ldap servers");
        }
        if (username == null || password == null || username.trim().length() == 0 || password.trim().length() == 0) {
            System.out.println("Username or password is empty");
            throw new FailedLoginException("Username or password is empty");
        }
        int retryCount = 0;
        int currentLdapUrlIndex = lastLdapUrlIndex;
        do {
            retryCount++;
            try {
                System.out.println("Setting up environment hash");
                Hashtable<Object, Object> env = new Hashtable<Object, Object>();
                env.put(Context.INITIAL_CONTEXT_FACTORY, CONTEXT_FACTORY_CLASS);
                env.put(Context.PROVIDER_URL, ldapServerUrls[currentLdapUrlIndex]);
                env.put("java.naming.ldap.attributes.binary", "objectGUID");
                env.put(Context.SECURITY_PRINCIPAL, username + "@" + domainName);
                env.put(Context.SECURITY_CREDENTIALS, password);
                DirContext ctx = new InitialDirContext(env);

                SearchControls constraints = new SearchControls();
                constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);

                NamingEnumeration answer = ctx.search("DC=mydcblox,DC=com", "sAMAccountName=" + username, constraints);
                if (answer.hasMore()) {
                    System.out.println("Found attribute! username:"+username);
                    this.attrs = ((SearchResult) answer.next()).getAttributes();
                }else{
                    System.out.println("Invalid User");
                    throw new Exception("Invalid User");
                }

                System.out.println("currentLdapUrlIndex"+currentLdapUrlIndex);
                lastLdapUrlIndex = currentLdapUrlIndex;
                return true;
            } catch (CommunicationException exp) {
                exp.printStackTrace();
                // if the exception of type communication we can assume the AD
                // is not reachable hence retry can be attempted with next
                // available AD
                if (retryCount < ldapServerUrls.length) {
                    currentLdapUrlIndex++;
                    if (currentLdapUrlIndex == ldapServerUrls.length) {
                        currentLdapUrlIndex = 0;
                    }
                    System.out.println("Trying next AD server...");
                    continue;
                }
                System.out.println("Not authorized");
                return false;
            } catch (Throwable throwable) {
                System.out.println("Auth thrown error");
                throwable.printStackTrace();
                return false;
            }
        } while (true);
    }

    private static String prefixZeros(int value) {
        if (value <= 0xF) {
            StringBuilder sb = new StringBuilder("0");
            sb.append(Integer.toHexString(value));

            return sb.toString();

        } else {
            return Integer.toHexString(value);
        }
    }

    public boolean initialize() {
        APIClient apiClient = new APIClient();
        try {
            apiClient.login("install", "install");
            this.identityAPI = apiClient.getIdentityAPI();
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public void addMembership(Membership membership) throws Exception {
        Boolean init = this.initialize();
        Long userId = Long.valueOf(membership.getUser_id());
        Long groupId = Long.valueOf(membership.getGroup_id());
        Long roleId = Long.valueOf(membership.getRole_id());
        if (init) {
            try {
                UserMembership userMembership = identityAPI.addUserMembership(userId, groupId, roleId);
            } catch (Exception e) {
                System.out.format("Could not add user %s to group %s with role %s", userId, groupId, roleId);
                e.printStackTrace();
                throw new Exception(e.getMessage());
            }
        } else {
            System.out.format("Could not connect with install install");
        }
    }

    public BonitaUserCustomDetail createGUID(String guid, String userId) throws Exception {
        Boolean init = this.initialize();
        Long luserId = Long.valueOf(userId);
        if (init) {
            try {
                List<CustomUserInfoDefinition> defs = identityAPI.getCustomUserInfoDefinitions(0,100);
                for (CustomUserInfoDefinition def : defs) {
                    if (def.getName().toLowerCase().contains("guid")) {
                        identityAPI.setCustomUserInfoValue(def.getId(), luserId, guid);
                    }
                }
            } catch (Exception e) {
                System.out.format("Could not add GUID %s to user %s", guid, userId);
                e.printStackTrace();
                throw new Exception(e.getMessage());
            }
        } else {
            System.out.format("Could not connect with install install");
        }
        return null;
    }


    public APISession loginUser(String userName, String password) {
        APIClient apiClient = new APIClient();
        try {
            apiClient.login(userName, password);
            APISession session = loginAPI.login(userName, password);
            Long tenant = session.getTenantId();
            System.out.format("Logged user %s in with %s and tenant set to %s", userName, password, tenant);
            return session;
        } catch (Exception e) {
            System.out.format("Could not login as user %s", userName);
        }
        return null;
    }

    public UserWithContactData createProfessionalContactDetails(BonitaUserContactDetails contactDetails) {
        Boolean init = this.initialize();
        if (init) {
            Long userId = Long.valueOf(contactDetails.getId());
            try {
                UserWithContactData user = identityAPI.getUserWithProfessionalDetails(userId);
                ContactData contactData = user.getContactData();
                ContactDataUpdater proContactUpdater = new ContactDataUpdater();
                proContactUpdater.setEmail(contactDetails.getEmail());
                UserUpdater updater = new UserUpdater();
                updater.setEnabled(true);
                updater.setProfessionalContactData(proContactUpdater);
                identityAPI.updateUser(userId, updater);
                return user;
            } catch (Exception e) {
                System.out.format("Could not get data for user %s <%s>", contactDetails.getId(), contactDetails.getEmail());
            }
        }
        return null;
    }

    public UserWithContactData updateProfessionalContactDetails(BonitaUserContactDetails contactDetails) {
        Boolean init = this.initialize();
        if (init) {
            Long userId = Long.valueOf(contactDetails.getId());
            try {
                UserWithContactData user = identityAPI.getUserWithProfessionalDetails(userId);
                ContactData contactData = user.getContactData();
                ContactDataUpdater perContactUpdater = new ContactDataUpdater();
                perContactUpdater.setEmail(contactDetails.getEmail());
                UserUpdater updater = new UserUpdater();
                updater.setEnabled(true);
                updater.setPersonalContactData(perContactUpdater);
                identityAPI.updateUser(userId, updater);
                return user;
            } catch (Exception e) {
                System.out.format("Could not get data for user %s <%s>", contactDetails.getId(), contactDetails.getEmail());
            }
        }
        return null;
    }

    public UserWithContactData  getUserIdentificationResponse (String userid) {
        Boolean init = this.initialize();
        if (init) {
            Long userId = Long.valueOf(userid);
            try {
                return identityAPI.getUserWithProfessionalDetails(userId);
            } catch (Exception e) {
                System.out.format("Could not get data for user %s", userid);
            }
        }
        return null;
    }

    public User createUser(UserCreateRequest userCreateRequest) {
        Boolean init = this.initialize();
        if (init) {
            UserCreator creator = new UserCreator(userCreateRequest.getUserName(), userCreateRequest.getPassword());
            creator.setFirstName(userCreateRequest.getFirstname())
                    .setLastName(userCreateRequest.getLastname())
                    .setEnabled(true);
            try {
                return identityAPI.createUser(creator);
            } catch (AlreadyExistsException e) {
                System.out.format("Could not create user %s as it already exists", userCreateRequest.getUserName());
            } catch (Exception e) {
                System.out.format("Could not create user %s", userCreateRequest.getUserName());
            }
        }
        return null;
    }

    private static UserIdentificationResponse mapUserIdentification(String responseString) {
        UserIdentificationResponse response = new UserIdentificationResponse();
        try {
            response = mapper.readValue(responseString, UserIdentificationResponse.class);
        } catch (IOException e) {
            response.setError("Error "+e.toString());
        }
        return response;
    }
}
