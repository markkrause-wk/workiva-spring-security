package com.workiva.security;

import com.workiva.platform.iam.alpha.authentication.core.Environment;
import com.workiva.platform.iam.alpha.authentication.core.jwt.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.jose4j.base64url.Base64Url;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwx.CompactSerializer;
import org.springframework.security.oauth2.jwt.*;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * A {@link JwtDecoder} to decode IAM generated tokens into a {@link Jwt} objects.
 *
 *
 * @see TokenVerifierImpl
 * @see TokenVerifier.Builder#build()
 */
@Slf4j
public class WorkivaJwtDecoder implements JwtDecoder {

    private final TokenParser tokenParser;
    private final Map<String, IamIssuer> iamIssuers;

    public WorkivaJwtDecoder() {
        // build a new WorkivaJwtDecoder with same pattern as TokenVerifier.Builder.build()
        if (Environment.getIamUnsafe() && Environment.isDeployed()) {
            throw new IllegalStateException("Refusing to build an unsafe WorkivaJwtDecoder in a deployed environment.");
        }

        // build the IamIssuer map just like TokenVerifier.Builder.build()
        iamIssuers = new HashMap<>();
        String serviceIssuers = Environment.getVariable("WORKIVA_IAM_ISSUERS");
        if (StringUtils.isNotBlank(serviceIssuers)) {
            Arrays
                .stream(StringUtils.split(serviceIssuers))
                .forEach(issuer -> iamIssuers.put(issuer, new IamIssuer(issuer)));
        }
        iamIssuers.put(Environment.getIamHost(), new IamIssuer());
        tokenParser = new TokenParserImpl();
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        JwtClaims jwtClaims = getJwtClaims(token);

        Map<String, Object> claims = new HashMap<>(jwtClaims.flattenClaims());
        Instant issuedAt = updateTimestampClaim(claims, JwtClaimNames.IAT);
        Instant expiresAt = updateTimestampClaim(claims, JwtClaimNames.EXP);
        // scopes are used for GrantedAuthority(s) in the JwtGrantedAuthoritiesConverter
        updateCollectionFromString(claims, "scope");
        updateCollectionFromString(claims, "scp");

        Map<String, Object> headers = new HashMap<>();
        headers.put("typ", "JWT");
        headers.put("alg", ""); // value could be identified, but is ignored

        return new Jwt(token, issuedAt, expiresAt, headers, claims);
    }

    /**
     * Parse the given {@code token} into {@link JwtClaims} with the environment appropriate
     */
    private JwtClaims getJwtClaims(String token) {
        JwtClaims jwtClaims;

        if (Environment.getIamUnsafe() && Environment.isDeployed()) {
            // similar to TokenVerifier.Builder.build(), we don't allow "unsafe" decoding in deploy environments
            throw new JwtException("Refusing to decode a token unsafely in a deployed environment.");
        } else if (Environment.getIamUnsafe()) {
            try {
                log.debug("Skipping token verification because Environment.getIamUnsafe() == true");
                String encodedClaims = CompactSerializer.deserialize(token)[1];
                jwtClaims = JwtClaims.parse(Base64Url.decodeToUtf8String(encodedClaims));
            } catch (InvalidJwtException e) {
                throw new BadJwtException("Failed to (unsafely) parse JwtClaims", e);
            }
        } else {
            try {
                final String issuer = tokenParser.getIssuer(token);
                IamIssuer iamIssuer = iamIssuers.get(issuer);
                if (null == iamIssuer) {
                    throw new JwtException(String.format("Untrusted issuer: %s", issuer));
                }
                jwtClaims = iamIssuer.getVerificationConsumer().processToClaims(token);
            } catch (InvalidJwtException e) {
                throw new BadJwtException("Failed to parse JwtClaims", e);
            } catch (IOException e) {
                throw new JwtException("Failed to get correct JwtConsumer", e);
            }
        }
        return jwtClaims;
    }

    @SuppressWarnings("unchecked")
    private Instant updateTimestampClaim(Map<String, Object> claims, String claimName) {
        Object obj = claims.get(claimName);
        if (obj instanceof Collection) {
            // assumes a collection of Long, with only one entry
            Optional<Long> seconds = ((Collection<Long>) obj).stream().findFirst();
            seconds.ifPresent(sec -> claims.put(claimName, Instant.ofEpochSecond(sec)));
        }
        return (Instant) claims.get(claimName);
    }

    @SuppressWarnings("unchecked")
    private void updateCollectionFromString(Map<String, Object> claims, String claimName) {
        Object obj = claims.get(claimName);
        if (obj instanceof String && StringUtils.containsWhitespace((String) obj)) {
            String[] strings = StringUtils.split((String) obj);
            claims.put(claimName, List.of(strings));
        } else if (obj instanceof Collection) {
            // assumes a collection of strings
            List<String> allStrings =
                ((Collection<String>) obj).stream()
                    .flatMap(s -> Stream.of(StringUtils.split(s)))
                    .collect(Collectors.toList());
            claims.put(claimName, allStrings);
        }
    }
}
