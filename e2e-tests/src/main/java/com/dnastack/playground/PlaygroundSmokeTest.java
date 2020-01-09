package com.dnastack.playground;

import com.dnastack.BaseE2eTest;
import io.restassured.http.ContentType;
import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

public class PlaygroundSmokeTest extends BaseE2eTest {

    @Test
    public void healthCheck() {
        given()
            .log().method()
            .log().uri()
        .when()
            .get("/oidc/.well-known/openid-configuration")
        .then()
            .log().ifValidationFails()
            .statusCode(200);
    }
}
