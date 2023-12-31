package com.caito.authorizationserver.infrastructure.services.contracts;

import com.caito.authorizationserver.api.models.requests.AppUserRequest;

/**
 * @author claudio.vilas
 * date 12/2023
 * description contrato de servicos de usarios
 */
public interface AppUserService {
    void createAppUser(AppUserRequest request);

}
