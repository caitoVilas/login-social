package com.caito.authorizationserver.domain.repositories;

import com.caito.authorizationserver.domain.entities.Role;
import com.caito.authorizationserver.utils.enums.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author claudio.vilas
 * date 12/2023
 * description repositorio para roles de usuario
 */

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
    Optional<Role> findByRoleName(RoleName roleName);
}
