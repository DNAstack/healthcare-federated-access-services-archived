package com.dnastack;

import io.restassured.RestAssured;
import org.junit.Before;

import static org.junit.Assert.fail;

public class BaseE2eTest {

    @Before
    public void setUp() throws Exception {
        RestAssured.baseURI = requiredEnv("E2E_BASE_URI");
    }

    protected String requiredEnv(String name) {
        String val = System.getenv(name);
        if (val == null) {
            fail("Environnment variable `" + name + "` is required");
        }
        return val;
    }

    protected String optionalEnv(String name, String defaultValue) {
        String val = System.getenv(name);
        if (val == null) {
            return defaultValue;
        }
        return val;
    }
}
