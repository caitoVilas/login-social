package com.caito.authorizationserver.domain.repositories;

import com.caito.authorizationserver.domain.entities.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * @author claudio.vilas
 * date 01/2024
 * description repositorio clase Client
 */

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {
    Optional<Client> findByClientId(String clientId);
}
