package com.caito.authorizationserver.api.exceptions.customs;

import lombok.Getter;
import lombok.Setter;

/**
 * @author claudio.vilas
 * date 12/2023
 * description excepcion personalizada para BadRequestException
 */

@Getter
@Setter
public class BadRequestException extends RuntimeException{
    private  String[] messages;
    public BadRequestException(String[] messages) {
        this.messages = messages;
        //super(messages);
    }
}
