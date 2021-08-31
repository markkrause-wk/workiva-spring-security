package com.workiva.security;

import com.workiva.platform.iam.alpha.authentication.core.jwt.TokenParser;
import com.workiva.platform.iam.alpha.authentication.core.jwt.TokenParserImpl;
import com.workiva.platform.iam.alpha.authentication.core.principals.WorkivaPrincipal;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * A {@link } {@link Converter Converter&lt;Jwt, AbstractAuthenticationToken&gt;} for converting {@link Jwt}
 * objects into valid {@link AbstractAuthenticationToken}s.
 *
 * @see org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter
 */
public class WorkivaJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private TokenParser tokenParser = new TokenParserImpl();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        try {
            Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
            WorkivaPrincipal wPrincipal = tokenParser.parseToken(jwt.getTokenValue());
            return new WorkivaAuthenticationToken(authorities, wPrincipal, jwt.getTokenValue());
        } catch (Exception e) {
            OAuth2Error oAuth2Error = BearerTokenErrors.invalidToken("Invalid Workiva JWT");
            throw new OAuth2AuthenticationException(oAuth2Error, e);
        }
    }

    /**
     * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;}
     * to use. Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @see JwtGrantedAuthoritiesConverter
     */
    public void setJwtGrantedAuthoritiesConverter(
        Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter
    ) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }

    /**
     * Sets the {@link TokenParser} to use. Defaults to {@link TokenParserImpl}.
     *
     * @see TokenParser
     */
    public void setTokenParser(TokenParser tokenParser) {
        Assert.notNull(tokenParser, "tokenParser cannot be null");
        this.tokenParser = tokenParser;
    }
}
