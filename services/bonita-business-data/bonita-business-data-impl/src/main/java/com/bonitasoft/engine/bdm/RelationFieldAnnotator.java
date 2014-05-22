package com.bonitasoft.engine.bdm;

import static org.apache.commons.lang3.StringUtils.left;

import javax.persistence.CascadeType;
import javax.persistence.FetchType;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.OrderColumn;

import com.bonitasoft.engine.bdm.model.field.RelationField;
import com.bonitasoft.engine.bdm.model.field.RelationField.Type;
import com.sun.codemodel.JAnnotationArrayMember;
import com.sun.codemodel.JAnnotationUse;
import com.sun.codemodel.JDefinedClass;
import com.sun.codemodel.JFieldVar;

/**
 * @author Colin PUY
 */
public class RelationFieldAnnotator {

    private CodeGenerator codeGenerator;

    public RelationFieldAnnotator(CodeGenerator codeGenerator) {
        this.codeGenerator = codeGenerator;
    }

    public void annotateRelationField(JDefinedClass entityClass, final RelationField field, final JFieldVar fieldVar) {
        JAnnotationUse relation = null;
        if (field.isCollection()) {
            relation = annotateMultipleReference(entityClass, field, fieldVar);
        } else {
            relation = annotateSingleReference(field, fieldVar);
        }

        relation.param("fetch", FetchType.EAGER);

        if (field.getType() == Type.COMPOSITION) {
            final JAnnotationArrayMember cascade = relation.paramArray("cascade");
            cascade.param(CascadeType.ALL);
        }
    }

    private JAnnotationUse annotateSingleReference(final RelationField field, final JFieldVar fieldVar) {
        JAnnotationUse relation;
        if (field.getType() == Type.AGGREGATION) {
            relation = codeGenerator.addAnnotation(fieldVar, ManyToOne.class);
        } else {
            relation = codeGenerator.addAnnotation(fieldVar, OneToOne.class);
        }
        addJoinColumn(fieldVar, field.getName());
        relation.param("optional", field.isNullable());
        return relation;
    }

    private JAnnotationUse annotateMultipleReference(JDefinedClass entityClass, final RelationField field, final JFieldVar fieldVar) {
        JAnnotationUse relation;
        if (field.getType() == Type.AGGREGATION) {
            relation = codeGenerator.addAnnotation(fieldVar, ManyToMany.class);
            addJoinTable(entityClass, field, fieldVar);

        } else {
            relation = codeGenerator.addAnnotation(fieldVar, OneToMany.class);
            JAnnotationUse joinColumn = addJoinColumn(fieldVar, entityClass.name());
            joinColumn.param("nullable", false);
        }
        codeGenerator.addAnnotation(fieldVar, OrderColumn.class);
        return relation;
    }

    private void addJoinTable(JDefinedClass entityClass, final RelationField field, final JFieldVar fieldVar) {
        JAnnotationUse joinTable = codeGenerator.addAnnotation(fieldVar, JoinTable.class);
        joinTable.param("name", getJoinTableName(entityClass.name(), field.getName()));

        JAnnotationArrayMember joinColumns = joinTable.paramArray("joinColumns");
        final JAnnotationUse nameQueryAnnotation = joinColumns.annotate(JoinColumn.class);
        nameQueryAnnotation.param("name", getJoinColumnName(entityClass.name()));

        JAnnotationArrayMember inverseJoinColumns = joinTable.paramArray("inverseJoinColumns");
        final JAnnotationUse a = inverseJoinColumns.annotate(JoinColumn.class);
        a.param("name", getJoinColumnName(field.getReference().getSimpleName()));
    }

    private JAnnotationUse addJoinColumn(final JFieldVar fieldVar, String columnName) {
        JAnnotationUse joinColumn = codeGenerator.addAnnotation(fieldVar, JoinColumn.class);
        joinColumn.param("name", getJoinColumnName(columnName));
        return joinColumn;
    }

    /**
     * Split names to 26 char to avoid joinColumn names longer than 30 char
     * protected for testing
     */
    protected String getJoinColumnName(String entityName) {
        return left(entityName.toUpperCase(), 26) + "_PID";
    }

    /**
     * Split names to 14 chars max to avoid joinTable names longer than 30 char (oracle restriction).
     * protected for testing
     */
    protected String getJoinTableName(String entityName, String relatedEntityName) {
        String name = left(entityName.toUpperCase(), 14);
        String refName = left(relatedEntityName.toUpperCase(), 14);
        return name + "_" + refName;
    }
}
