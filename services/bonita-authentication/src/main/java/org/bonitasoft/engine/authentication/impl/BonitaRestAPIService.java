package org.bonitasoft.engine.authentication.impl;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.bonitasoft.engine.api.*;
import org.bonitasoft.engine.authentication.impl.model.*;
import org.bonitasoft.engine.exception.AlreadyExistsException;
import org.bonitasoft.engine.identity.*;
import org.bonitasoft.engine.session.APISession;
import java.io.IOException;
import java.util.List;

public class  BonitaRestAPIService {
    private static final ObjectMapper mapper = new ObjectMapper();
    private static APIAccessor apiAccessor;
    private IdentityAPI identityAPI;
    private LoginAPI loginAPI;

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


