package com.caito.authorizationserver.infrastructure.services.impl;

import com.caito.authorizationserver.api.models.requests.AppUserRequest;
import com.caito.authorizationserver.domain.entities.AppUser;
import com.caito.authorizationserver.domain.entities.Role;
import com.caito.authorizationserver.domain.repositories.AppUserRepository;
import com.caito.authorizationserver.domain.repositories.RoleRepository;
import com.caito.authorizationserver.infrastructure.services.contracts.AppUserService;
import com.caito.authorizationserver.utils.enums.RoleName;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

/**
 * @author claudio.vilas
 * date 12/2023
 * description implemetacion contratos AppUserService
 */

@Service
@Slf4j
@RequiredArgsConstructor
public class AppUserServiceImpl implements AppUserService {
    private final AppUserRepository appUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void createAppUser(AppUserRequest request) {
        log.info("---> inicio servicio crear usuario");
        var user = AppUser.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .expired(false)
                .locked(false)
                .credentialExpired(false)
                .disabled(false)
                .build();
        Set<Role> roles = new HashSet<>();
        roles.add(roleRepository.findByRoleName(RoleName.ROLE_ADMIN).get());
        log.info("---> guardar usuario...");
        user.setRoles(roles);
        appUserRepository.save(user);
        log.info("---> finalizado servicio guardar usuario");
    }
}
