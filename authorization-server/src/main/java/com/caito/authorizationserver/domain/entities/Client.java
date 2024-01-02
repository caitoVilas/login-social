package com.caito.authorizationserver.domain.entities;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.util.Date;
import java.util.Set;

/**
 * @author claudio.vilas
 * date 01/2024
 * description
 */

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class Client {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private String id;
    private String clientId;
    private String clientSecret;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<ClientAuthenticationMethod> authenticationMethods;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> redirectUris;
    @ElementCollection(fetch = FetchType.EAGER)
    private Set<String> scopes;
    private boolean requireProofKey;

    public static RegisteredClient toRegisterdClient(Client client){
        RegisteredClient.Builder builder = RegisteredClient.withId(client.getClientId())
                .clientId(client.getClientId())
                .clientSecret(client.clientSecret)
                .clientIdIssuedAt(new Date().toInstant())
                .clientAuthenticationMethods(am -> am.addAll(client.getAuthenticationMethods()))
                .authorizationGrantTypes(agt -> agt.addAll(client.getAuthorizationGrantTypes()))
                .redirectUris(ru -> ru.addAll(client.getRedirectUris()))
                .scopes(sc -> sc.addAll(client.getScopes()))
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(client.isRequireProofKey()).build());
        return builder.build();
    }
}
