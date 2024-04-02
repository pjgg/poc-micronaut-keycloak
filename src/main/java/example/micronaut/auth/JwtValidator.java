package example.micronaut.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import jakarta.inject.Singleton;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

@Singleton
public class JwtValidator {

    private List<String> JWKS = List.of("http://localhost:8080/realms/realmOne/protocol/openid-connect/certs", "http://localhost:8080/realms/realmTwo/protocol/openid-connect/certs");
    private List<ConfigurableJWTProcessor<SecurityContext>> jwtProcessors;

    public JwtValidator() throws MalformedURLException {
        jwtProcessors = new ArrayList<>(JWKS.size());
        for(String jwk : JWKS) {
            ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource = JWKSourceBuilder
                    .create(new URL(jwk))
                    .retrying(true)
                    .build();
            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor.setJWSKeySelector(keySelector);
//            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
//                    new JWTClaimsSet.Builder().issuer("https://demo.c2id.com").build(),
//                    new HashSet<>(Arrays.asList(
//                            JWTClaimNames.SUBJECT,
//                            JWTClaimNames.ISSUED_AT,
//                            JWTClaimNames.EXPIRATION_TIME,
//                            "scp",
//                            "cid",
//                            JWTClaimNames.JWT_ID))));
            jwtProcessors.add(jwtProcessor);
        }
    }

    public JWTClaimsSet verify(String accessToken) throws JOSEException, BadJOSEException {
        accessToken = accessToken.replace("Bearer", "").trim();
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet = null;

        for(ConfigurableJWTProcessor<SecurityContext> jwtProcessor : jwtProcessors){
            try {
                claimsSet = jwtProcessor.process(accessToken, ctx);
            } catch (ParseException | BadJOSEException e) {
                // invalid token
            }
        }

        if(Objects.isNull(claimsSet)){
            throw new BadJOSEException("Invalid token");
        }

        return claimsSet;
    }
}
