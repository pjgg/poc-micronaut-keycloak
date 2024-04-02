package example.micronaut.auth;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MediaType;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.QueryValue;
import io.micronaut.http.client.HttpClient;
import io.micronaut.http.client.annotation.Client;
import io.micronaut.http.cookie.Cookie;
import io.micronaut.scheduling.TaskExecutors;
import io.micronaut.scheduling.annotation.ExecuteOn;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.rules.SecurityRule;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Controller("/oauth")
public class KeycloakAuthController {

    private final HttpClient httpClient;

    private final static String OAUTH_KEYCLOAK_URL = "http://localhost:8080/realms/%s/protocol/openid-connect/auth?"
            + "scope=openid+email+profile"
            + "&client_id=%s"
            + "&redirect_uri=%s"
            + "&response_type=code"
            +"&state=%s";

    private static final String TOKEN_ENDPOINT = "/realms/%s/protocol/openid-connect/token";

    private static final String KEYCLOAK_DOMAIN = "http://localhost:8080/";

    private final static String STATE_TEMPLATE = "{\"nonce\":\"%s\",\"redirectUri\":\"%s\"}";

    private record RealmDetails(String clientId, String redirectUri, String clientSecret){}

    private Map<String, RealmDetails> keycloakCache = new HashMap<>();
    private ObjectMapper objectMapper;

    public KeycloakAuthController(@Client(KEYCLOAK_DOMAIN) HttpClient httpClient) throws UnsupportedEncodingException {
        // This should come from Keycloak
        var realmOne = new RealmDetails("myclient", URLEncoder.encode("http://localhost:8081/oauth/callback/keycloak", "UTF-8"), "HemUWicHEJsywGLhCoDgOBdsIJ1clh3h");
        var realmTwo = new RealmDetails("myclient", URLEncoder.encode("http://localhost:8081/oauth/callback/keycloak", "UTF-8"), "JTCh0Y6bLSCAfztWiTQuRSg2weWqAI7E");
        keycloakCache.put("realmOne", realmOne);
        keycloakCache.put("realmTwo", realmTwo);
        this.httpClient = httpClient;
        this.objectMapper = new ObjectMapper();
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get("/login/keycloak/{orgId}")
    public HttpResponse<Void> redirectToKeycloakLogin(@PathVariable("orgId") String orgId) {
        RealmDetails realm = keycloakCache.get(orgId);
        String nonce = generateCodeVerifier();
        String state = generateState(nonce, realm.redirectUri());
        String keycloakAuthorizationUrl = String.format(OAUTH_KEYCLOAK_URL, orgId, realm.clientId, realm.redirectUri, state);
        return HttpResponse.redirect(URI.create(keycloakAuthorizationUrl));
    }

    @Secured(SecurityRule.IS_ANONYMOUS)
    @Get("/callback/keycloak")
    @ExecuteOn(TaskExecutors.BLOCKING)
    public HttpResponse<Object> callback(@QueryValue("state") String state,
                                       @QueryValue("session_state") String sessionState,
                                       @QueryValue("iss") String iss,
                                         @QueryValue("code") String code
    ) throws UnsupportedEncodingException, JsonProcessingException {
        String org = "realmOne";
        if(iss.contains("realmTwo")){
            org = "realmTwo";
        }
        String secret = keycloakCache.get(org).clientSecret();

        String endpoint = String.format(TOKEN_ENDPOINT, org);
        HttpRequest<String> request = HttpRequest.POST(endpoint, "")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("grant_type=authorization_code&code=" + code + "&client_id=myclient&redirect_uri=" + URLEncoder.encode("http://localhost:8081/oauth/callback/keycloak", "UTF-8") + "&client_secret=" + secret);

        HttpResponse<String> response = httpClient.toBlocking().exchange(request, String.class);
        JsonNode jsonNode = objectMapper.readTree(response.body());
        String accessToken = jsonNode.get("access_token").asText();

        Cookie cookie = Cookie.of("jwtToken", accessToken);
        return HttpResponse.redirect(URI.create("/home")).cookie(cookie);
    }

    private String generateState(String nonce, String redirectUrl) {
        String state = String.format(STATE_TEMPLATE, nonce, redirectUrl);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(state.getBytes());
    }

    private String generateCodeVerifier() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
