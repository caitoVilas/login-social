package com.caito.authorizationserver.api.controllers;

import com.caito.authorizationserver.api.models.requests.AppUserRequest;
import com.caito.authorizationserver.infrastructure.services.contracts.AppUserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author claudio.vilas
 * date 12/2023
 * description controlador para servicios de usuarios
 */

@RestController
@RequestMapping("/api/v1/users")
@Slf4j
@RequiredArgsConstructor
public class AppUserController {
    private final AppUserService appUserService;

    @PostMapping("/create")
    public ResponseEntity<?> createAppUser(@RequestBody AppUserRequest request){
        log.info("#### endpoint creacion de usuarios ####");
        appUserService.createAppUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
}
