package com.caito.authorizationserver.infrastructure.services.impl;

import com.caito.authorizationserver.api.exceptions.customs.BadRequestException;
import com.caito.authorizationserver.api.exceptions.customs.NotFoundException;
import com.caito.authorizationserver.api.models.requests.AppUserRequest;
import com.caito.authorizationserver.domain.entities.AppUser;
import com.caito.authorizationserver.domain.entities.Role;
import com.caito.authorizationserver.domain.repositories.AppUserRepository;
import com.caito.authorizationserver.domain.repositories.RoleRepository;
import com.caito.authorizationserver.infrastructure.services.contracts.AppUserService;
import com.caito.authorizationserver.utils.constants.RoleConst;
import com.caito.authorizationserver.utils.constants.UserConst;
import com.caito.authorizationserver.utils.enums.RoleName;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        this.validateUser(request);
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
        roles.add(roleRepository.findByRoleName(RoleName.ROLE_ADMIN)
                .orElseThrow(()->{
                    log.error("ERROR: ".concat(RoleConst.R_NOT_FOUND));
                    return new NotFoundException(RoleConst.R_NOT_FOUND);
                }));
        user.setRoles(roles);
        log.info("---> guardar usuario...");
        appUserRepository.save(user);
        log.info("---> finalizado servicio guardar usuario");
    }

    private void validateUser(AppUserRequest request){
        List<String> messages = new ArrayList<>();
        log.info("--> validando entradas...");

        if (request.getUsername() == null || request.getUsername().isBlank()){
            log.error("ERROR: ".concat(UserConst.U_USERNAME_EMPTY));
            messages.add(UserConst.U_USERNAME_EMPTY);
        }
        if (appUserRepository.existsByUsername(request.getUsername())){
            log.error("ERROR: ".concat(UserConst.U_USERNAME_EXISTS).concat(request.getUsername()));
            messages.add(UserConst.U_USERNAME_EXISTS.concat(request.getUsername()));
        }
        if (request.getEmail() == null || request.getEmail().isBlank()){
            log.error("ERROR: ".concat(UserConst.U_EMAIL_EMPTY));
            messages.add(UserConst.U_EMAIL_EXISTS);
        }else if (appUserRepository.existsByEmail(request.getEmail())){
            log.error("ERROR: ".concat(UserConst.U_EMAIL_EXISTS).concat(request.getEmail()));
            messages.add(UserConst.U_EMAIL_EXISTS.concat(request.getEmail()));
        }else if (!this.validateEmail(request.getEmail())){
            log.error("ERROR:".concat(UserConst.U_EMAIL_MALFORMED));
            messages.add(UserConst.U_EMAIL_MALFORMED);
        }
        if (!messages.isEmpty()){
            String[] response = new String[messages.size()];
            response = messages.toArray(response);
            throw new BadRequestException(response);
        }
    }

    private boolean validateEmail(String email){
        Pattern pattern =
          Pattern.compile("^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$");
        Matcher matcher = pattern.matcher(email);
        if (matcher.find()){
            log.info("---> mail valido");
            return true;
        }else {
            return false;
        }
    }
}
