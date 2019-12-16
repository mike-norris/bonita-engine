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
package org.bonitasoft.engine.business.data.impl;

import java.util.Collections;
import java.util.Set;

import org.hibernate.boot.archive.scan.spi.ClassDescriptor;
import org.hibernate.boot.archive.scan.spi.MappingFileDescriptor;
import org.hibernate.boot.archive.scan.spi.PackageDescriptor;
import org.hibernate.boot.archive.scan.spi.ScanEnvironment;
import org.hibernate.boot.archive.scan.spi.ScanOptions;
import org.hibernate.boot.archive.scan.spi.ScanParameters;
import org.hibernate.boot.archive.scan.spi.ScanResult;
import org.hibernate.boot.archive.scan.spi.Scanner;

/**
 * @author Matthieu Chaffotte
 * @author Emmanuel Duchastenier
 */
public class InactiveScanner implements Scanner {

    @Override
    public ScanResult scan(ScanEnvironment environment, ScanOptions options, ScanParameters params) {
        return new ScanResult() {

            @Override
            public Set<PackageDescriptor> getLocatedPackages() {
                return Collections.emptySet();
            }

            @Override
            public Set<ClassDescriptor> getLocatedClasses() {
                return Collections.emptySet();
            }

            @Override
            public Set<MappingFileDescriptor> getLocatedMappingFiles() {
                return Collections.emptySet();
            }
        };
    }
}
