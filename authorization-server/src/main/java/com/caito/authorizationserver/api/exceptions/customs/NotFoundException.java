package com.caito.authorizationserver.api.exceptions.customs;

/**
 * @author claudio.vilas
 * date 12/2023
 * description excepcion parsonalizada para elemento no encontrado
 */
public class NotFoundException extends RuntimeException{
    public NotFoundException(String message) {
        super(message);
    }
}
