package com.caito.authorizationserver.api.models.responses;

import com.caito.authorizationserver.utils.enums.RoleName;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

/**
 * @author claudio.vilas
 * date 12/2023
 * description modelo que representa un rol para las respuestas
 */

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class RoleResponse implements Serializable {
    private Long id;
    private RoleName roleName;
}
