package example.micronaut.auth;

import io.micronaut.security.authentication.AuthenticationRequest;

public class JwtAuthenticationRequest implements AuthenticationRequest<String, Object> {

    private final String token;

    public JwtAuthenticationRequest(String token) {
        this.token = token;
    }

    @Override
    public String getIdentity() {
        return token;
    }

    @Override
    public Object getSecret() {
        return null; // Not applicable for JWT
    }
}
