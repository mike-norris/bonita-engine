/*******************************************************************************
 * Copyright (C) 2014 BonitaSoft S.A.
 * BonitaSoft is a trademark of BonitaSoft SA.
 * This software file is BONITASOFT CONFIDENTIAL. Not For Distribution.
 * For commercial licensing information, contact:
 * BonitaSoft, 32 rue Gustave Eiffel – 38000 Grenoble
 * or BonitaSoft US, 51 Federal Street, Suite 305, San Francisco, CA 94107
 ******************************************************************************/
package com.bonitasoft.engine.business.application.impl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bonitasoft.engine.builder.BuilderFactory;
import org.bonitasoft.engine.commons.exceptions.SObjectAlreadyExistsException;
import org.bonitasoft.engine.commons.exceptions.SObjectCreationException;
import org.bonitasoft.engine.commons.exceptions.SObjectModificationException;
import org.bonitasoft.engine.commons.exceptions.SObjectNotFoundException;
import org.bonitasoft.engine.events.model.SDeleteEvent;
import org.bonitasoft.engine.events.model.SInsertEvent;
import org.bonitasoft.engine.events.model.SUpdateEvent;
import org.bonitasoft.engine.events.model.builders.SEventBuilderFactory;
import org.bonitasoft.engine.persistence.QueryOptions;
import org.bonitasoft.engine.persistence.ReadPersistenceService;
import org.bonitasoft.engine.persistence.SBonitaReadException;
import org.bonitasoft.engine.persistence.SelectByIdDescriptor;
import org.bonitasoft.engine.persistence.SelectOneDescriptor;
import org.bonitasoft.engine.queriablelogger.model.SQueriableLogSeverity;
import org.bonitasoft.engine.recorder.Recorder;
import org.bonitasoft.engine.recorder.SRecorderException;
import org.bonitasoft.engine.recorder.model.DeleteRecord;
import org.bonitasoft.engine.recorder.model.EntityUpdateDescriptor;
import org.bonitasoft.engine.recorder.model.InsertRecord;
import org.bonitasoft.engine.recorder.model.UpdateRecord;
import org.bonitasoft.engine.services.QueriableLoggerService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.bonitasoft.engine.business.application.ApplicationService;
import com.bonitasoft.engine.business.application.impl.cleaner.ApplicationDestructor;
import com.bonitasoft.engine.business.application.impl.cleaner.ApplicationMenuDestructor;
import com.bonitasoft.engine.business.application.impl.cleaner.ApplicationPageDestructor;
import com.bonitasoft.engine.business.application.impl.converter.MenuIndexConverter;
import com.bonitasoft.engine.business.application.model.SApplication;
import com.bonitasoft.engine.business.application.model.SApplicationMenu;
import com.bonitasoft.engine.business.application.model.SApplicationPage;
import com.bonitasoft.engine.business.application.model.builder.SApplicationMenuBuilder;
import com.bonitasoft.engine.business.application.model.builder.SApplicationMenuUpdateBuilder;
import com.bonitasoft.engine.business.application.model.builder.SApplicationUpdateBuilder;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationBuilderFactoryImpl;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationMenuBuilderFactoryImpl;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationMenuFields;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationMenuUpdateBuilderFactoryImpl;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationMenuUpdateBuilderImpl;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationPageBuilderFactoryImpl;
import com.bonitasoft.engine.business.application.model.builder.impl.SApplicationUpdateBuilderFactoryImpl;
import com.bonitasoft.manager.Features;
import com.bonitasoft.manager.Manager;

@RunWith(MockitoJUnitRunner.class)
public class ApplicationServiceImplTest {

    private static final String DELETED_SUFFIX = "_DELETED";

    private static final String CREATED_SUFFIX = "_CREATED";

    private static final int CREATED_BY = 10;

    private static final String APPLICATION_TOKEN = "app";

    private static final String APPLICATION_DISP_NAME = "My app";

    public static final int MAX_RESULTS = 2;

    @Mock
    private Manager managerActiveFeature;

    @Mock
    private Manager managerDisabledFeature;

    @Mock
    private Recorder recorder;

    @Mock
    private ReadPersistenceService persistenceService;

    @Mock
    private QueriableLoggerService queriableLogService;

    @Mock
    private IndexManager indexManager;

    @Mock
    private MenuIndexConverter convertor;

    @Mock
    private ApplicationDestructor applicationDestructor;

    @Mock
    private ApplicationPageDestructor applicationPageDestructor;

    @Mock
    private ApplicationMenuDestructor applicationMenuDestructor;

    private SApplication application;

    private ApplicationServiceImpl applicationServiceActive;

    private ApplicationServiceImpl applicationServiceDisabled;

    @Before
    public void setUp() throws Exception {
        given(managerActiveFeature.isFeatureActive(Features.BUSINESS_APPLICATIONS)).willReturn(true);
        given(managerDisabledFeature.isFeatureActive(Features.BUSINESS_APPLICATIONS)).willReturn(false);
        applicationServiceActive = new ApplicationServiceImpl(managerActiveFeature, recorder, persistenceService, queriableLogService, indexManager, convertor,
                applicationDestructor, applicationPageDestructor, applicationMenuDestructor);
        applicationServiceDisabled = new ApplicationServiceImpl(managerDisabledFeature, recorder, persistenceService, queriableLogService, indexManager,
                convertor, applicationDestructor, applicationPageDestructor, applicationMenuDestructor);

        when(queriableLogService.isLoggable(anyString(), any(SQueriableLogSeverity.class))).thenReturn(true);
        application = buildApplication(APPLICATION_TOKEN, APPLICATION_DISP_NAME);
        application.setId(10L);
    }

    private SApplication buildApplication(final String applicationName, final String applicationDisplayName) {
        return new SApplicationBuilderFactoryImpl().createNewInstance(applicationName, applicationDisplayName, "1.0", CREATED_BY).done();
    }

    @Test
    public void createApplication_should_call_recordInsert_and_return_created_object() throws Exception {
        //given
        final SInsertEvent insertEvent = (SInsertEvent) BuilderFactory.get(SEventBuilderFactory.class).createInsertEvent(ApplicationService.APPLICATION)
                .setObject(application).done();
        final InsertRecord record = new InsertRecord(application);

        //when
        final SApplication createdApplication = applicationServiceActive.createApplication(application);

        //then
        assertThat(createdApplication).isEqualTo(application);
        verify(recorder, times(1)).recordInsert(record, insertEvent);
    }

    @Test(expected = SObjectCreationException.class)
    public void createApplication_should_throw_SObjectCreationException_when_record_insert_throws_Exception() throws Exception {
        //given
        doThrow(new SRecorderException("")).when(recorder).recordInsert(any(InsertRecord.class), any(SInsertEvent.class));

        //when
        applicationServiceActive.createApplication(application);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void createApplication_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.createApplication(buildApplication(APPLICATION_TOKEN, APPLICATION_DISP_NAME));

        //then exception
    }

    @Test
    public void createApplication_should_throw_SObjectAlreadyExistsException_when_an_application_with_the_same_name_already_exists() throws Exception {
        //given
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplication>("getApplicationByToken", Collections.<String, Object> singletonMap("name",
                APPLICATION_TOKEN), SApplication.class))).willReturn(application);

        final SApplication newApp = buildApplication(APPLICATION_TOKEN, APPLICATION_DISP_NAME);

        //when
        try {
            applicationServiceActive.createApplication(newApp);
            fail("Exception expected");
        } catch (final SObjectAlreadyExistsException e) {
            //then
            assertThat(e.getMessage()).isEqualTo("An application already exists with token '" + APPLICATION_TOKEN + "'.");
            verify(recorder, never()).recordInsert(any(InsertRecord.class), any(SInsertEvent.class));
        }

    }

    @Test
    public void getApplication_should_return_result_of_persistence_service_selectById() throws Exception {
        //given
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, 10L))).willReturn(application);

        //when
        final SApplication retrievedApp = applicationServiceActive.getApplication(10L);

        //then
        assertThat(retrievedApp).isEqualTo(application);
    }

    @Test
    public void getApplication_should_throw_SObjectNotFoundException_when_persitence_service_returns_null() throws Exception {
        //given
        final long applicationId = 10L;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(null);

        //when
        try {
            applicationServiceActive.getApplication(applicationId);
            fail("Exception expected");
        } catch (final SObjectNotFoundException e) {
            //then
            assertThat(e.getMessage()).isEqualTo("No application found with id '" + applicationId + "'.");
        }

    }

    @Test(expected = IllegalStateException.class)
    public void getApplication_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getApplication(15L);

        //then exception
    }

    @Test
    public void getApplicationByToken_should_return_result_of_persitence_service_getApplicationByToken() throws Exception {
        //given
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplication>("getApplicationByToken", Collections.<String, Object> singletonMap("name",
                APPLICATION_TOKEN), SApplication.class))).willReturn(application);

        //when
        final SApplication retriedApplication = applicationServiceActive.getApplicationByToken(APPLICATION_TOKEN);

        //then
        assertThat(retriedApplication).isEqualTo(application);

    }

    @Test
    public void deleteApplication_should_call_record_delete() throws Exception {
        //given
        final long applicationId = 10L;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(
                application);

        //when
        applicationServiceActive.deleteApplication(applicationId);

        //then
        final SDeleteEvent event = (SDeleteEvent) BuilderFactory.get(SEventBuilderFactory.class).createDeleteEvent(ApplicationService.APPLICATION)
                .setObject(application).done();
        verify(recorder, times(1)).recordDelete(new DeleteRecord(application), event);
    }

    @Test
    public void deleteApplication_should_call_applicationDestructor() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);

        final long applicationId = 10L;
        final SApplication app = buildApplication("app", "my app");
        app.setId(27);
        doReturn(app).when(applicationService).getApplication(applicationId);

        //when
        applicationService.deleteApplication(applicationId);

        //then
        verify(applicationDestructor, times(1)).onDeleteApplication(app);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void deleteApplication_should_throw_SObjectNotFoundException_when_no_application_with_the_given_id_is_found() throws Exception {
        //given
        final long applicationId = 10L;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(null);

        //when
        applicationServiceActive.deleteApplication(applicationId);

        //then exception
    }

    @Test(expected = SObjectModificationException.class)
    public void deleteApplication_should_throw_SObjectModificationException_when_recorder_throws_SRecorderException() throws Exception {
        //given
        final long applicationId = 10L;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(
                application);
        doThrow(new SRecorderException("")).when(recorder).recordDelete(any(DeleteRecord.class), any(SDeleteEvent.class));

        //when
        applicationServiceActive.deleteApplication(applicationId);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void deleteApplication_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.deleteApplication(15L);

        //then exception
    }

    @Test
    public void getNumberOfApplications_should_return_the_result_of_persitenceService_getNumberOfEntities() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        final long count = 7;
        given(persistenceService.getNumberOfEntities(SApplication.class, options, null)).willReturn(count);

        //when
        final long nbOfApp = applicationServiceActive.getNumberOfApplications(options);

        //then
        assertThat(nbOfApp).isEqualTo(count);
    }

    @Test(expected = IllegalStateException.class)
    public void getNumberOfApplications_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getNumberOfApplications(new QueryOptions(0, 10));

        //then exception
    }

    @Test
    public void searchApplications_should_return_the_result_of_persitenceService_searchEntity() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        final List<SApplication> applications = new ArrayList<SApplication>(1);
        applications.add(mock(SApplication.class));
        given(persistenceService.searchEntity(SApplication.class, options, null)).willReturn(applications);

        //when
        final List<SApplication> retrievedApplications = applicationServiceActive.searchApplications(options);

        //then
        assertThat(retrievedApplications).isEqualTo(applications);
    }

    @Test(expected = SBonitaReadException.class)
    public void searchApplications_should_throw_SBonitaReadException_when_persistenceSevice_throws_SBonitaReadException() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        given(applicationServiceActive.searchApplications(options)).willThrow(new SBonitaReadException(""));

        //when
        applicationServiceActive.searchApplications(options);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void searchApplications_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.searchApplications(new QueryOptions(0, 10));

        //then exception
    }

    private SApplicationPage buildApplicationPage(final long applicationId, final long pageId, final String name) {
        return new SApplicationPageBuilderFactoryImpl().createNewInstance(applicationId, pageId, name).done();
    }

    private SApplicationPage buildApplicationPage(final long applicationPageId, final long applicationId, final long pageId, final String pageToken) {
        final SApplicationPage applicationPage = buildApplicationPage(applicationId, pageId, pageToken);
        applicationPage.setId(applicationPageId);
        return applicationPage;
    }

    @Test
    public void createApplicationPage_should_call_recordInsert_and_return_created_object() throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(15, 5, 15, "mainDashBoard");
        final SInsertEvent insertEvent = (SInsertEvent) BuilderFactory.get(SEventBuilderFactory.class).createInsertEvent(ApplicationService.APPLICATION_PAGE)
                .setObject(applicationPage).done();
        final InsertRecord record = new InsertRecord(applicationPage);

        //when
        final SApplicationPage createdApplicationPage = applicationServiceActive.createApplicationPage(applicationPage);

        //then
        assertThat(createdApplicationPage).isEqualTo(applicationPage);
        verify(recorder, times(1)).recordInsert(record, insertEvent);
    }

    @Test(expected = SObjectCreationException.class)
    public void createApplicationPage_should_throw_SObjectCreationException_when_recorder_throws_SBonitaException() throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(15, 5, 15, "mainDashBoard");
        doThrow(new SRecorderException("")).when(recorder).recordInsert(any(InsertRecord.class), any(SInsertEvent.class));

        //when
        applicationServiceActive.createApplicationPage(applicationPage);

        //then exception
    }

    @Test(expected = SObjectAlreadyExistsException.class)
    public void createApplicationPage_should_throw_SObjectAlreadyExistsException_when_an_applicationPage_with_the_same_name_in_the_same_application_exists()
            throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(5, 15, "mainDashBoard");
        final Map<String, Object> inputParameters = new HashMap<String, Object>(2);
        inputParameters.put("applicationId", 5);
        inputParameters.put("applicationPageToken", "mainDashBoard");
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplicationPage>("getApplicationPageByTokenAndApplicationId", inputParameters,
                SApplicationPage.class
                ))).willReturn(applicationPage);

        //when
        final SApplicationPage applicationPageToCreate = buildApplicationPage(7, 5, 16, "mainDashBoard");
        applicationServiceActive.createApplicationPage(applicationPageToCreate);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void createApplicationPage_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.createApplicationPage(buildApplicationPage(5, 15, "mainDashBoard"));

        //then exception
    }

    @Test
    public void getApplicationPage_should_return_result_of_persitence_service_selectById() throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(10, 20, "myPage");
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationPage>("getApplicationPageById", SApplicationPage.class, 10L))).willReturn(
                applicationPage);

        //when
        final SApplicationPage retrievedAppPage = applicationServiceActive.getApplicationPage(10L);

        //then
        assertThat(retrievedAppPage).isEqualTo(applicationPage);
    }

    @Test
    public void getApplicationPage_by_name_and_appName_should_return_result_of_persitence_service_selectOne() throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(10, 20, "myPage");
        final Map<String, Object> inputParameters = new HashMap<String, Object>(2);
        inputParameters.put("applicationName", "app");
        inputParameters.put("applicationPageToken", "firstPage");
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplicationPage>("getApplicationPageByTokenAndApplicationToken", inputParameters,
                SApplicationPage.class
                ))).willReturn(applicationPage);

        //when
        final SApplicationPage retrievedAppPage = applicationServiceActive.getApplicationPage("app", "firstPage");

        //then
        assertThat(retrievedAppPage).isEqualTo(applicationPage);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void getApplicationPage_by_name_and_appName_should_throw_SObjectNotFoundException_when_persitence_service_selectOne_returns_null() throws Exception {
        //given
        given(persistenceService.selectOne(Matchers.<SelectOneDescriptor<SApplicationPage>> any())).willReturn(null);

        //when
        applicationServiceActive.getApplicationPage("app", "firstPage");

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void getApplicationPage_by_name_and_appName_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getApplicationPage(APPLICATION_TOKEN, "myPage");

        //then exception
    }

    @Test
    public void deleteApplicationPage_should_call_record_delete_with_applicationPage_identified_by_the_given_id() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        final long applicationPageId = 10L;
        final SApplicationPage applicationPage = buildApplicationPage(applicationPageId, 20, 30, "myPage");
        doReturn(applicationPage).when(applicationService).getApplicationPage(applicationPageId);
        final long applicationId = 20L;
        doReturn(application).when(applicationService).getApplication(applicationId);

        //when
        applicationService.deleteApplicationPage(applicationPageId);

        //then
        final ArgumentCaptor<SDeleteEvent> deleteEventCaptor = ArgumentCaptor.forClass(SDeleteEvent.class);
        final ArgumentCaptor<DeleteRecord> deleteRecordCaptor = ArgumentCaptor.forClass(DeleteRecord.class);
        verify(recorder, times(1)).recordDelete(deleteRecordCaptor.capture(), deleteEventCaptor.capture());
        assertThat(deleteRecordCaptor.getValue().getEntity()).isEqualTo(applicationPage);
        assertThat(deleteEventCaptor.getValue().getType()).isEqualTo(ApplicationService.APPLICATION_PAGE + DELETED_SUFFIX);
        assertThat(deleteEventCaptor.getValue().getObject()).isEqualTo(applicationPage);
    }

    @Test
    public void deleteApplicationPage_should_call_applicationPageDestructor() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);

        //application page
        final long applicationPageId = 10L;
        final long applicationId = 20L;
        final SApplicationPage applicationPage = buildApplicationPage(applicationPageId, applicationId, 30, "myPage");
        doReturn(applicationPage).when(applicationService).getApplicationPage(applicationPageId);

        //when
        applicationService.deleteApplicationPage(applicationPage);

        //then
        verify(applicationPageDestructor, times(1)).onDeleteApplicationPage(applicationPage);
    }

    @Test(expected = SObjectModificationException.class)
    public void deleteApplicationPage_should_throw_SObjectModificationException_when_applicationPageDestructor_throws_SObjectModificationException()
            throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);

        //application page
        final long applicationPageId = 10L;
        final long applicationId = 20L;
        final SApplicationPage applicationPage = buildApplicationPage(applicationPageId, applicationId, 30, "myPage");
        doReturn(applicationPage).when(applicationService).getApplicationPage(applicationPageId);
        doThrow(new SObjectModificationException()).when(applicationPageDestructor).onDeleteApplicationPage(applicationPage);

        //when
        applicationService.deleteApplicationPage(applicationPage);

        //then exception
    }

    @Test(expected = SObjectNotFoundException.class)
    public void deleteApplicationPage_should_throw_SObjectNotFound_when_there_is_no_applicationPage_for_the_given_id() throws Exception {
        //given
        final long applicationPageId = 10L;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationPage>("getApplicationPageById", SApplicationPage.class, applicationPageId)))
                .willReturn(null);

        //when
        applicationServiceActive.deleteApplicationPage(applicationPageId);

        //then exception
    }

    @Test(expected = SObjectModificationException.class)
    public void deleteApplicationPage_should_throw_SObjectModificationException_when_recorder_throws_SRecorderException() throws Exception {
        //given
        final long applicationPageId = 10L;
        final SApplicationPage applicationPage = buildApplicationPage(27, 20, 30, "myPage");
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationPage>("getApplicationPageById", SApplicationPage.class, applicationPageId)))
                .willReturn(applicationPage);
        doThrow(new SRecorderException("")).when(recorder).recordDelete(any(DeleteRecord.class), any(SDeleteEvent.class));

        //when
        applicationServiceActive.deleteApplicationPage(applicationPageId);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void deleteApplicationPage_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.deleteApplicationPage(10L);

        //then exception
    }

    @Test
    public void updateApplication_should_call_recorder_recordUpdate_and_return_updated_object() throws Exception {
        //given
        final SApplicationUpdateBuilder updateBuilder = new SApplicationUpdateBuilderFactoryImpl().createNewInstance(0L);
        updateBuilder.updateDisplayName("new display name");
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final int applicationId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(
                application);

        //when
        final SApplication updatedApplication = applicationServiceActive.updateApplication(applicationId, updateDescriptor);

        //then
        final UpdateRecord updateRecord = UpdateRecord.buildSetFields(application,
                updateDescriptor);
        final SUpdateEvent updateEvent = (SUpdateEvent) BuilderFactory.get(SEventBuilderFactory.class).createUpdateEvent(ApplicationService.APPLICATION)
                .setObject(application).done();
        verify(recorder, times(1)).recordUpdate(updateRecord, updateEvent);
        assertThat(updatedApplication).isEqualTo(application);
    }

    @Test(expected = SObjectModificationException.class)
    public void updateApplication_should_throw_SObjectModificationException_if_set_homepage_references_invalid_page() throws Exception {
        //given
        final SApplicationUpdateBuilder updateBuilder = new SApplicationUpdateBuilderFactoryImpl().createNewInstance(0L);
        final long homePageId = 150L;
        updateBuilder.updateHomePageId(homePageId);
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final int applicationId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplication>("getApplicationById", SApplication.class, applicationId))).willReturn(
                application);

        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationPage>("getApplicationPageById", SApplicationPage.class, homePageId)))
                .willReturn(
                        null);

        //when
        applicationServiceActive.updateApplication(applicationId, updateDescriptor);

        //then exception
    }

    @Test(expected = SObjectNotFoundException.class)
    public void updateApplication_should_throw_SObjectModificationException_when_recorder_throws_SRecorderException() throws Exception {
        //given
        final EntityUpdateDescriptor updateDescriptor = new EntityUpdateDescriptor();
        updateDescriptor.addField("name", "newName");
        final int applicationId = 17;

        doThrow(new SRecorderException("")).when(recorder).recordUpdate(any(UpdateRecord.class), any(SUpdateEvent.class));

        //when
        applicationServiceActive.updateApplication(applicationId, updateDescriptor);

        //then exception
    }

    @Test(expected = SObjectAlreadyExistsException.class)
    public void updateApplication_should_throw_SObjectAlreadyExistsException_when_another_application_exists_with_the_same_name() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        final SApplicationUpdateBuilder updateBuilder = new SApplicationUpdateBuilderFactoryImpl().createNewInstance(0L);
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.updateToken("newToken").done();

        final int applicationId = 17;
        doReturn(application).when(applicationService).getApplication(applicationId);
        doReturn(true).when(applicationService).hasApplicationWithToken("newToken");

        //when
        applicationService.updateApplication(applicationId, updateDescriptor);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void updateApplication_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        final EntityUpdateDescriptor updateDescriptor = new EntityUpdateDescriptor();
        updateDescriptor.addField("name", "newName");
        applicationServiceDisabled.updateApplication(10L, updateDescriptor);

        //then exception
    }

    @Test
    public void getApplicationHomePage_should_return_result_of_persitence_service_selectOne() throws Exception {
        //given
        final SApplicationPage applicationPage = buildApplicationPage(10, 20, "myPage");
        final Map<String, Object> inputParameters = new HashMap<String, Object>(2);
        inputParameters.put("applicationId", 100);
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplicationPage>("getApplicationHomePage", inputParameters,
                SApplicationPage.class
                ))).willReturn(applicationPage);

        //when
        final SApplicationPage homePage = applicationServiceActive.getApplicationHomePage(100);

        //then
        assertThat(homePage).isEqualTo(applicationPage);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void getApplicationHomePage_should_throw_SObjectNotFoundException_when_persitence_service_selectOne_returns_null() throws Exception {
        //given
        final Map<String, Object> inputParameters = new HashMap<String, Object>(2);
        inputParameters.put("applicationId", 100);
        given(persistenceService.selectOne(new SelectOneDescriptor<SApplicationPage>("getApplicationHomePage", inputParameters,
                SApplicationPage.class
                ))).willReturn(null);

        //when
        applicationServiceActive.getApplicationHomePage(100);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void getApplicationHomePage_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getApplicationHomePage(11L);

        //then exception
    }

    @Test
    public void getNumberOfApplicationPages_should_return_the_result_of_persitenceService_getNumberOfEntities() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        final long count = 7;
        given(persistenceService.getNumberOfEntities(SApplicationPage.class, options, null)).willReturn(count);

        //when
        final long nbOfApp = applicationServiceActive.getNumberOfApplicationPages(options);

        //then
        assertThat(nbOfApp).isEqualTo(count);
    }

    @Test(expected = IllegalStateException.class)
    public void getNumberOfApplicationPages_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getNumberOfApplicationPages(new QueryOptions(0, 10));

        //then exception
    }

    @Test
    public void searchApplicationPages_should_return_the_result_of_persitenceService_searchEntity() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        final List<SApplicationPage> applicationPages = new ArrayList<SApplicationPage>(1);
        applicationPages.add(mock(SApplicationPage.class));
        given(persistenceService.searchEntity(SApplicationPage.class, options, null)).willReturn(applicationPages);

        //when
        final List<SApplicationPage> retrievedAppPages = applicationServiceActive.searchApplicationPages(options);

        //then
        assertThat(retrievedAppPages).isEqualTo(applicationPages);
    }

    @Test(expected = SBonitaReadException.class)
    public void searchApplicationPages_should_throw_SBonitaReadException_when_persistenceSevice_throws_SBonitaReadException() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        given(applicationServiceActive.searchApplicationPages(options)).willThrow(new SBonitaReadException(""));

        //when
        applicationServiceActive.searchApplicationPages(options);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void searchApplicationPages_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.searchApplicationPages(new QueryOptions(0, 10));

        //then exception
    }

    @Test
    public void createApplicationMenu_should_call_recordInsert_and_return_created_object() throws Exception {
        //given
        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, 1, 12);
        appMenu.setId(15);

        //when
        final SApplicationMenu createdAppMenu = applicationServiceActive.createApplicationMenu(appMenu);

        //then
        assertThat(createdAppMenu).isEqualTo(appMenu);

        final ArgumentCaptor<SInsertEvent> insertEventCaptor = ArgumentCaptor.forClass(SInsertEvent.class);
        final ArgumentCaptor<InsertRecord> insertRecordCaptor = ArgumentCaptor.forClass(InsertRecord.class);
        verify(recorder, times(1)).recordInsert(insertRecordCaptor.capture(), insertEventCaptor.capture());
        assertThat(insertRecordCaptor.getValue().getEntity()).isEqualTo(appMenu);
        assertThat(insertEventCaptor.getValue().getObject()).isEqualTo(appMenu);
        assertThat(insertEventCaptor.getValue().getType()).isEqualTo(ApplicationService.APPLICATION_MENU + CREATED_SUFFIX);
    }

    private SApplicationMenu buildApplicationMenu(final String displayName, final long applicationPageId, final int index, final long applicationId) {
        final SApplicationMenuBuilder builder = new SApplicationMenuBuilderFactoryImpl()
                .createNewInstance(displayName, applicationId, applicationPageId, index);
        return builder.done();
    }

    @Test(expected = SObjectCreationException.class)
    public void createApplicationMenu_should_throw_SObjectCreationException_when_recorder_throws_Exception() throws Exception {
        //given
        doThrow(new SRecorderException("")).when(recorder).recordInsert(any(InsertRecord.class), any(SInsertEvent.class));

        //when
        applicationServiceActive.createApplicationMenu(buildApplicationMenu("main", 4, 1, 12));

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void createApplicationMenu_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.createApplicationMenu(buildApplicationMenu("main", 5, 1, 12));

        //then exception
    }

    @Test
    public void updateApplicationMenu_should_call_recorder_recordUpdate_and_return_updated_object() throws Exception {
        //given
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderImpl();
        updateBuilder.updateDisplayName("new display name");
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, 1, 12);
        appMenu.setId(17);

        final int applicationMenuId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById", SApplicationMenu.class, applicationMenuId)))
                .willReturn(
                        appMenu);

        //when
        final SApplicationMenu updatedApplicationMenu = applicationServiceActive.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then
        final UpdateRecord updateRecord = UpdateRecord.buildSetFields(appMenu,
                updateDescriptor);
        final SUpdateEvent updateEvent = (SUpdateEvent) BuilderFactory.get(SEventBuilderFactory.class).createUpdateEvent(ApplicationService.APPLICATION_MENU)
                .setObject(appMenu).done();
        verify(recorder, times(1)).recordUpdate(updateRecord, updateEvent);
        assertThat(updatedApplicationMenu).isEqualTo(appMenu);
    }

    @Test
    public void updateApplicationMenu_should_organize_indexes_when_field_index_is_updated() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        final int newIndexValue = 1;
        final int oldIndexValue = 5;
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderImpl();
        updateBuilder.updateIndex(newIndexValue);
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final int applicationMenuId = 17;
        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, oldIndexValue, 12);
        appMenu.setId(applicationMenuId);

        doReturn(appMenu).when(applicationService).getApplicationMenu(applicationMenuId);

        final MenuIndex newIndex = new MenuIndex(null, newIndexValue, 5);
        final MenuIndex oldIndex = new MenuIndex(null, oldIndexValue, 6);
        given(convertor.toMenuIndex(appMenu)).willReturn(oldIndex);
        given(convertor.toMenuIndex(appMenu, updateDescriptor)).willReturn(newIndex);

        //when
        applicationService.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then
        verify(indexManager, times(1)).organizeIndexesOnUpdate(oldIndex, newIndex);
    }

    @Test
    public void updateApplicationMenu_should_force_update_index_when_field_parent_is_updated() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderImpl();
        updateBuilder.updateParentId(28L);
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final int applicationMenuId = 17;
        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, 4, 12);
        appMenu.setId(applicationMenuId);

        doReturn(appMenu).when(applicationService).getApplicationMenu(applicationMenuId);

        final MenuIndex newIndex = new MenuIndex(28L, 6, 5);
        final MenuIndex oldIndex = new MenuIndex(null, 4, 6);
        given(convertor.toMenuIndex(appMenu)).willReturn(oldIndex);
        given(convertor.toMenuIndex(appMenu, updateDescriptor)).willReturn(newIndex);
        given(applicationService.getLastUsedIndex(28L)).willReturn(5);

        //when
        applicationService.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then
        final ArgumentCaptor<UpdateRecord> updateRecordCaptor = ArgumentCaptor.forClass(UpdateRecord.class);
        verify(recorder, times(1)).recordUpdate(updateRecordCaptor.capture(), any(SUpdateEvent.class));

        final UpdateRecord updateRecord = updateRecordCaptor.getValue();
        assertThat(updateRecord.getFields().get(SApplicationMenuFields.INDEX)).isEqualTo(6);
    }

    @Test
    public void updateApplicationMenu_should_not_organize_indexes_when_field_index_is_not_updated() throws Exception {
        //given
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderImpl();
        updateBuilder.updateDisplayName("new display name");
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, 1, 12);
        appMenu.setId(17);

        final int applicationMenuId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById", SApplicationMenu.class, applicationMenuId)))
                .willReturn(
                        appMenu);

        //when
        applicationServiceActive.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then
        verifyZeroInteractions(indexManager);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void updateApplicationMenu_should_throw_SObjectNotFoundException_when_recorder_returns_null() throws Exception {
        //given
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderImpl();
        updateBuilder.updateDisplayName("new display name");
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final int applicationMenuId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById", SApplicationMenu.class, applicationMenuId)))
                .willReturn(
                        null);

        //when
        applicationServiceActive.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then exception
    }

    @Test(expected = SObjectModificationException.class)
    public void updateApplicationMenu_should_throw_SObjectModificationException_when_recorder_throws_SRecorderException() throws Exception {
        //given
        final SApplicationMenuUpdateBuilder updateBuilder = new SApplicationMenuUpdateBuilderFactoryImpl().createNewInstance();
        updateBuilder.updateDisplayName("new display name");
        final EntityUpdateDescriptor updateDescriptor = updateBuilder.done();

        final SApplicationMenu appMenu = buildApplicationMenu("main", 5, 1, 12);
        appMenu.setId(17);

        final int applicationMenuId = 17;
        given(persistenceService.selectById(new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById", SApplicationMenu.class, applicationMenuId)))
                .willReturn(
                        appMenu);
        doThrow(new SRecorderException("")).when(recorder).recordUpdate(any(UpdateRecord.class), any(SUpdateEvent.class));

        //when
        applicationServiceActive.updateApplicationMenu(applicationMenuId, updateDescriptor);

        //then exception
    }

    @Test
    public void getApplicationMenu_by_id_should_return_result_of_persitence_service() throws Exception {
        //given
        final SApplicationMenu applicationMenu = buildApplicationMenu("main", 2, 1, 12);
        final SelectByIdDescriptor<SApplicationMenu> selectDescriptor = new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById",
                SApplicationMenu.class, 3);
        given(persistenceService.selectById(selectDescriptor)).willReturn(applicationMenu);

        //when
        final SApplicationMenu retrivedAppMenu = applicationServiceActive.getApplicationMenu(3);

        //then
        assertThat(retrivedAppMenu).isEqualTo(applicationMenu);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void getApplicationMenu_by_id_should_throw_SObjectNotFoundException_when_persitence_service_returns_null() throws Exception {
        //given
        final SelectByIdDescriptor<SApplicationMenu> selectDescriptor = new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById",
                SApplicationMenu.class, 3);
        given(persistenceService.selectById(selectDescriptor)).willReturn(null);

        //when
        applicationServiceActive.getApplicationMenu(3);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void getApplicationMenu_by_id_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getApplicationMenu(1);

        //then exception
    }

    @Test
    public void deleteApplicationMenu_should_delete_application_menu_identified_for_the_given_identifier() throws Exception {
        //given
        final int applicationMenuId = 3;
        final SApplicationMenu applicationMenu = buildApplicationMenu("main", 2, 1, 12);
        applicationMenu.setId(applicationMenuId);
        final SelectByIdDescriptor<SApplicationMenu> selectDescriptor = new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById",
                SApplicationMenu.class, applicationMenuId);
        given(persistenceService.selectById(selectDescriptor)).willReturn(applicationMenu);
        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForRootMenu", Collections.<String, Object> emptyMap(),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(2);

        //when
        applicationServiceActive.deleteApplicationMenu(applicationMenuId);

        //then
        final ArgumentCaptor<SDeleteEvent> deleteEventCaptor = ArgumentCaptor.forClass(SDeleteEvent.class);
        final ArgumentCaptor<DeleteRecord> deleteRecordCaptor = ArgumentCaptor.forClass(DeleteRecord.class);
        verify(recorder, times(1)).recordDelete(deleteRecordCaptor.capture(), deleteEventCaptor.capture());
        assertThat(deleteEventCaptor.getValue().getObject()).isEqualTo(applicationMenu);
        assertThat(deleteEventCaptor.getValue().getType()).isEqualTo(ApplicationService.APPLICATION_MENU + DELETED_SUFFIX);
        assertThat(deleteRecordCaptor.getValue().getEntity()).isEqualTo(applicationMenu);
    }

    @Test
    public void deleteApplicationMenu_should_call_applicationMenuDestructor() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);

        final int applicationMenuId = 3;
        final SApplicationMenu applicationMenu = buildApplicationMenu("main", 2, 1, 12);
        applicationMenu.setId(applicationMenuId);

        //when
        applicationService.deleteApplicationMenu(applicationMenu);

        //then
        verify(applicationMenuDestructor, times(1)).onDeleteApplicationMenu(applicationMenu);
    }

    @Test
    public void deleteApplicationMenu_without_parent_should_update_indexes() throws Exception {
        //given
        final int indexValue = 6;
        final int lastUsedIndex = 10;
        final int applicationId = 3;
        final SApplicationMenu applicationMenu = buildApplicationMenu("main", 2, indexValue, 12);
        applicationMenu.setId(applicationId);
        final SelectByIdDescriptor<SApplicationMenu> selectDescriptor = new SelectByIdDescriptor<SApplicationMenu>("getApplicationMenuById",
                SApplicationMenu.class, applicationId);
        given(persistenceService.selectById(selectDescriptor)).willReturn(applicationMenu);

        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForRootMenu", Collections.<String, Object> emptyMap(),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(lastUsedIndex);

        final MenuIndex menuIndex = new MenuIndex(null, indexValue, lastUsedIndex);
        given(convertor.toMenuIndex(applicationMenu)).willReturn(menuIndex);

        //when
        applicationServiceActive.deleteApplicationMenu(applicationId);

        //then
        verify(indexManager, times(1)).organizeIndexesOnDelete(menuIndex);
    }

    @Test(expected = SObjectNotFoundException.class)
    public void deleteApplicationMenu_should_throw_SObjectObjectNotFoundException_if_no_application_menu_is_found_with_the_given_id() throws Exception {
        //given
        given(persistenceService.selectById(Matchers.<SelectByIdDescriptor<SApplicationMenu>> any())).willReturn(null);

        //when
        applicationServiceActive.deleteApplicationMenu(5);

        //then exception
    }

    @Test(expected = SObjectModificationException.class)
    public void deleteApplicationMenu_should_throw_SObjectObjectModificationException_recorder_throws_exception() throws Exception {
        //given
        final SApplicationMenu applicationMenu = buildApplicationMenu("main", 1, 1, 12);
        given(persistenceService.selectById(Matchers.<SelectByIdDescriptor<SApplicationMenu>> any())).willReturn(applicationMenu);

        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForRootMenu", Collections.<String, Object> emptyMap(),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(2);

        doThrow(new SRecorderException("")).when(recorder).recordDelete(any(DeleteRecord.class), any(SDeleteEvent.class));

        //when
        applicationServiceActive.deleteApplicationMenu(5);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void deleteApplicationMenu_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.deleteApplicationMenu(1);

        //then exception
    }

    @Test
    public void getNumberOfApplicationMenus_should_return_the_result_of_persistenc_service() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 10);
        final long count = 7;
        given(persistenceService.getNumberOfEntities(SApplicationMenu.class, options, null)).willReturn(count);

        //when
        final long numberOfMenus = applicationServiceActive.getNumberOfApplicationMenus(options);

        //then
        assertThat(numberOfMenus).isEqualTo(count);
    }

    @Test(expected = IllegalStateException.class)
    public void getNumberOfApplicationMenus_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.getNumberOfApplicationMenus(new QueryOptions(0, 10));

        //then exception
    }

    @Test
    public void searchApplicationMenus_should_return_the_result_of_persistence_service() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 2);
        final List<SApplicationMenu> applicationMenus = new ArrayList<SApplicationMenu>(1);
        applicationMenus.add(mock(SApplicationMenu.class));
        given(persistenceService.searchEntity(SApplicationMenu.class, options, null)).willReturn(applicationMenus);

        //when
        final List<SApplicationMenu> retrievedAppMenus = applicationServiceActive.searchApplicationMenus(options);

        //then
        assertThat(retrievedAppMenus).isEqualTo(applicationMenus);
    }

    @Test(expected = SBonitaReadException.class)
    public void searchApplicationMenus_should_throw_SBontiaSearchException_when_persistence_service_throws_exception() throws Exception {
        //given
        final QueryOptions options = new QueryOptions(0, 2);
        given(persistenceService.searchEntity(SApplicationMenu.class, options, null)).willThrow(new SBonitaReadException(""));

        //when
        applicationServiceActive.searchApplicationMenus(options);

        //then exception
    }

    @Test(expected = IllegalStateException.class)
    public void searchApplicationMenus_should_throw_IllegalStateException_when_feature_is_not_available() throws Exception {
        //when
        applicationServiceDisabled.searchApplicationMenus(new QueryOptions(0, 10));

        //then exception
    }

    @Test
    public void getNextIndex_should_return_getLastUsedIndex_more_one() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        given(applicationService.getLastUsedIndex(4L)).willReturn(7);

        //when
        final int next = applicationServiceActive.getNextAvailableIndex(4L);

        //then
        assertThat(next).isEqualTo(8);
    }

    @Test
    public void executeGetLastUsedIndexQuery_should_use_persistence_service_getLastIndexForRootMenu_if_parent_is_null() throws Exception {
        //given
        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForRootMenu", Collections.<String, Object> emptyMap(),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(1);

        //when
        final Integer result = applicationServiceActive.executeGetLastUsedIndexQuery(null);

        //then
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void executeGetLastUsedIndexQuery_should_use_persistence_service_getLastIndexForChildOf_if_parent_is_not_null() throws Exception {
        //given
        final SApplicationMenuBuilderFactoryImpl factory = new SApplicationMenuBuilderFactoryImpl();
        final long parentId = 10;
        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForChildOf", Collections.<String, Object> singletonMap(
                factory.getParentIdKey(), parentId),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(1);

        //when
        final Integer result = applicationServiceActive.executeGetLastUsedIndexQuery(parentId);

        //then
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getLastUsedIndex_should_return_executeGetLastUsedIndexQuery_if_result_is_not_null() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        given(applicationService.executeGetLastUsedIndexQuery(1L)).willReturn(4);

        //when
        final int lastUsedIndex = applicationService.getLastUsedIndex(1L);

        //then
        assertThat(lastUsedIndex).isEqualTo(4);
    }

    @Test
    public void getLastUsedIndex_should_return_zero_executeGetLastUsedIndexQuery_if_result_is_null() throws Exception {
        //given
        final ApplicationServiceImpl applicationService = spy(applicationServiceActive);
        given(applicationService.executeGetLastUsedIndexQuery(1L)).willReturn(null);

        //when
        final int lastUsedIndex = applicationService.getLastUsedIndex(1L);

        //then
        assertThat(lastUsedIndex).isEqualTo(0);
    }

    @Test
    public void getLastUsedIndex_should_return_zero_when_persistence_service_getLastIndexForChildOf_return_null() throws Exception {
        //given
        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForRootMenu", Collections.<String, Object> emptyMap(),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(null);

        //when
        final Integer lastUsedIndex = applicationServiceActive.getLastUsedIndex(null);

        //then
        assertThat(lastUsedIndex).isEqualTo(0);
    }

    @Test
    public void getLastUsedIndex_for_child_menu_should_return_zero_when_persistence_service_getLastIndexForChildOf_return_null() throws Exception {
        //given
        final SApplicationMenuBuilderFactoryImpl factory = new SApplicationMenuBuilderFactoryImpl();
        final long parentId = 10;
        final SelectOneDescriptor<Integer> descriptor = new SelectOneDescriptor<Integer>("getLastIndexForChildOf", Collections.<String, Object> singletonMap(
                factory.getParentIdKey(), parentId),
                SApplicationMenu.class);
        given(persistenceService.selectOne(descriptor)).willReturn(null);

        //when
        final int next = applicationServiceActive.getLastUsedIndex(parentId);

        //then
        assertThat(next).isEqualTo(0);
    }

}