package example.micronaut.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micronaut.security.authentication.AuthenticationFailed;
import io.micronaut.security.authentication.AuthenticationResponse;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

@Singleton
public class CustomAuthenticationProvider {

    private JwtValidator jwtValidator;

    public CustomAuthenticationProvider(JwtValidator jwtValidator) {
        this.jwtValidator = jwtValidator;
    }

    public AuthenticationResponse authenticate(String jwt) {
        try {
            JWTClaimsSet claims = jwtValidator.verify(jwt);
            Map<String, Object> attributes = new HashMap<>();
            attributes.put("tenantId", claims.getClaim("organization"));
            attributes.put("preferred_username", claims.getClaim("preferred_username"));

            return AuthenticationResponse.success(claims.getSubject(), new ArrayList<>(), attributes);
        } catch (BadJOSEException | JOSEException e) {
            return new AuthenticationFailed("Invalid token");
        }
    }
}
