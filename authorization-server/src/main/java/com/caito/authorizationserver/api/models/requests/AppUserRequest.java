package com.caito.authorizationserver.api.models.requests;

import com.caito.authorizationserver.api.models.responses.RoleResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Set;

/**
 * @author claudio.vilas
 * date 12/20223
 * description modelo que representa un usuario para los request
 */

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class AppUserRequest implements Serializable {
    private Long id;
    private String username;
    private String password;
    private String email;
}
