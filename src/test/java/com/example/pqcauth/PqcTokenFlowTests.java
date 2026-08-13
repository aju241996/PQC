package com.example.pqcauth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end test of the PQC token authentication flow: login issues an
 * ML-DSA-signed token, the token grants access to a protected endpoint, and
 * requests without/with-bad tokens are rejected.
 */
@SpringBootTest
@AutoConfigureMockMvc
class PqcTokenFlowTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void publicKeyEndpointIsAccessibleWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/api/pqc/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm", is("ML_DSA_87")));
    }

    @Test
    void secureEndpointRejectsRequestsWithoutToken() throws Exception {
        mockMvc.perform(get("/api/secure/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void secureEndpointRejectsMalformedToken() throws Exception {
        mockMvc.perform(get("/api/secure/profile").header("Authorization", "Bearer not-a-real-token"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginThenAccessProtectedResourceWithPqcToken() throws Exception {
        String loginBody = objectMapper.writeValueAsString(new Object() {
            public final String username = "alice";
            public final String password = "changeit";
        });

        String responseJson = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm", is("ML_DSA_87")))
                .andReturn().getResponse().getContentAsString();

        JsonNode json = objectMapper.readTree(responseJson);
        String token = json.get("accessToken").asText();
        org.assertj.core.api.Assertions.assertThat(token.split("\\.")).hasSize(3);

        mockMvc.perform(get("/api/secure/profile").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username", is("alice")))
                .andExpect(jsonPath("$.roles[0]", is("USER")));
    }

    @Test
    void adminEndpointRejectsNonAdminToken() throws Exception {
        String loginBody = objectMapper.writeValueAsString(new Object() {
            public final String username = "alice";
            public final String password = "changeit";
        });
        String responseJson = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String token = objectMapper.readTree(responseJson).get("accessToken").asText();

        mockMvc.perform(get("/api/secure/admin/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void adminEndpointAllowsAdminToken() throws Exception {
        String loginBody = objectMapper.writeValueAsString(new Object() {
            public final String username = "admin";
            public final String password = "changeit";
        });
        String responseJson = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String token = objectMapper.readTree(responseJson).get("accessToken").asText();

        mockMvc.perform(get("/api/secure/admin/ping").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status", is("ok")));
    }
}
