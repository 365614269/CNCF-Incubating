/*
 * Copyright 2024 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.crypto.def.test;

import org.junit.Assume;
import org.junit.Before;
import org.keycloak.common.util.Environment;
import org.keycloak.sdjwt.sdjwtvp.SdJwtVPTest;

/**
 * Test with default security provider and non-fips bouncycastle
 *
 * @author <a href="mailto:francis.pouatcha@adorsys.com">Francis Pouatcha</a>
 */
public class DefaultCryptoSdJwtVPTest extends SdJwtVPTest {

    @Before
    public void before() {
        // Run this test just if java is not in FIPS mode
        Assume.assumeFalse("Java is in FIPS mode. Skipping the test.", Environment.isJavaInFipsMode());
    }
}
