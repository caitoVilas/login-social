package com.caito.authorizationserver.api.exceptions.controllers;

import com.caito.authorizationserver.api.exceptions.customs.BadRequestException;
import com.caito.authorizationserver.api.models.responses.ErrorsResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

/**
 * @author claudio.vilas
 * date 12/2023
 * description handler para manejar error BadRequestException
 */

@RestControllerAdvice
@ResponseStatus(HttpStatus.BAD_REQUEST)
public class BadRequestExceptionController {
    public ResponseEntity<ErrorsResponse> badRequestExceptionHandler(BadRequestException e,
                                                                     HttpServletRequest request){
        var response = ErrorsResponse.builder()
                .code(HttpStatus.BAD_REQUEST.value())
                .status(HttpStatus.BAD_REQUEST.name())
                .timestamp(LocalDateTime.now())
                .messages(e.getMessages())
                .path(request.getRequestURI())
                .build();
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }
}
