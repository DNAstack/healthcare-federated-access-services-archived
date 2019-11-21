package com.dnastack.ic;

import com.dnastack.BaseE2eTest;
import io.restassured.http.ContentType;
import org.junit.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

public class IcSmokeTest extends BaseE2eTest {

    @Test
    public void returnServiceInfo() {
        given()
            .log().method()
            .log().uri()
        .when()
            .header("Accept", "application/json")
            .get("/identity")
        .then()
            .log().ifValidationFails()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("name", equalTo("Identity Concentrator"))
            .body("startTime", not(isEmptyOrNullString()));
    }
}
