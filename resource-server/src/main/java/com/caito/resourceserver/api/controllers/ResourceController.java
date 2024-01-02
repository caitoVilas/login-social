package com.caito.resourceserver.api.controllers;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author claudio.vilas
 * date 01/2024
 * description controllador de recursos
 */

@RestController
@RequestMapping("/api/v1/resources")
@Slf4j
@RequiredArgsConstructor
public class ResourceController {


    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    private ResponseEntity<?> admin(Authentication authentication) {
        return ResponseEntity.ok().build();
    }
    @GetMapping("/user")
    public ResponseEntity<?> user(Authentication authentication){
        return ResponseEntity.ok().build();
    }

}
