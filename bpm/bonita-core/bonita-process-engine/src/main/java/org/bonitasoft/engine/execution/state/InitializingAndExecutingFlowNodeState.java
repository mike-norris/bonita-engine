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
package org.bonitasoft.engine.execution.state;

import org.bonitasoft.engine.core.process.definition.model.SProcessDefinition;
import org.bonitasoft.engine.core.process.instance.api.exceptions.SActivityStateExecutionException;
import org.bonitasoft.engine.core.process.instance.model.SFlowNodeInstance;
import org.bonitasoft.engine.core.process.instance.model.SStateCategory;
import org.bonitasoft.engine.execution.StateBehaviors;
import org.springframework.stereotype.Component;

@Component
public class InitializingAndExecutingFlowNodeState extends OnEnterAndFinishConnectorState {

    public static final int ID = 61;
    private final StateBehaviors stateBehaviors;

    public InitializingAndExecutingFlowNodeState(final StateBehaviors stateBehaviors) {
        super(stateBehaviors);
        this.stateBehaviors = stateBehaviors;
    }

    @Override
    public int getId() {
        return ID;
    }

    @Override
    public boolean isStable() {
        return false;
    }

    @Override
    public boolean isTerminal() {
        return false;
    }

    @Override
    public String getName() {
        return "executing";
    }

    @Override
    public boolean shouldExecuteState(final SProcessDefinition processDefinition,
            final SFlowNodeInstance flowNodeInstance) {
        return true;
    }

    @Override
    public SStateCategory getStateCategory() {
        return SStateCategory.NORMAL;
    }

    @Override
    public boolean mustAddSystemComment(final SFlowNodeInstance flowNodeInstance) {
        return false;
    }

    @Override
    public String getSystemComment(final SFlowNodeInstance flowNodeInstance) {
        return "";
    }

    @Override
    protected void beforeOnEnter(final SProcessDefinition processDefinition, final SFlowNodeInstance flowNodeInstance)
            throws SActivityStateExecutionException {

        stateBehaviors.createData(processDefinition, flowNodeInstance);
        stateBehaviors.mapActors(flowNodeInstance, processDefinition.getProcessContainer());
    }

    @Override
    protected void onEnterToOnFinish(final SProcessDefinition processDefinition,
            final SFlowNodeInstance flowNodeInstance)
            throws SActivityStateExecutionException {
        stateBehaviors.updateDisplayNameAndDescription(processDefinition, flowNodeInstance);
    }

    @Override
    protected void afterOnFinish(final SProcessDefinition processDefinition, final SFlowNodeInstance flowNodeInstance)
            throws SActivityStateExecutionException {
        stateBehaviors.updateDisplayDescriptionAfterCompletion(processDefinition, flowNodeInstance);
    }

}
