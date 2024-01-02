package com.caito.authorizationserver.api.models.requests;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.io.Serializable;
import java.util.Set;

/**
 * @author claudio.vilas
 * date 01/20234
 * description modelo para requisitos de Clients
 */

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ClientRequest implements Serializable {
    private String clientId;
    private String clientSecret;
    private Set<ClientAuthenticationMethod> authenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean requireProofKey;
}
