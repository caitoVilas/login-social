package com.caito.authorizationserver.infrastructure.services.impl;

import com.caito.authorizationserver.api.exceptions.customs.NotFoundException;
import com.caito.authorizationserver.domain.repositories.AppUserRepository;
import com.caito.authorizationserver.utils.constants.UserConst;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author claudio.vilas
 * date 12/2023
 * description
 */

@Service
@Slf4j
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final AppUserRepository appUserRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return appUserRepository.findByUsername(username)
                .orElseThrow(()->{
                    log.error("ERROR: ".concat(UserConst.U_NAME_NOT_FOUND) + username);
                    return new NotFoundException(UserConst.U_NAME_NOT_FOUND + username);
                });
    }
}
