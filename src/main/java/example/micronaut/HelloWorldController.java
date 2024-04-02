package example.micronaut;

import example.micronaut.auth.CustomAuthenticationProvider;
import io.micronaut.http.HttpStatus;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.Header;
import io.micronaut.http.exceptions.HttpStatusException;
import io.micronaut.security.annotation.Secured;
import io.micronaut.security.authentication.AuthenticationResponse;
import io.micronaut.security.rules.SecurityRule;
import jakarta.inject.Inject;

@Secured(SecurityRule.IS_ANONYMOUS) // a hack
@Controller("/hello")
public class HelloWorldController {

    @Inject
    private CustomAuthenticationProvider customAuthenticationProvider;

    @Get
    public String hello(@Header("Authorization") String jwt) {
        AuthenticationResponse authenticationResponse = customAuthenticationProvider.authenticate(jwt);
        if(!authenticationResponse.isAuthenticated()) {
            throw new HttpStatusException(HttpStatus.FORBIDDEN, "Access forbidden");
        }

        String org = (String) authenticationResponse.getAuthentication().get().getAttributes().get("tenantId");
        return "Hello, " + org + "!";
    }
}
