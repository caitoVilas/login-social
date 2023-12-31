package com.caito.authorizationserver.api.exceptions.controllers;

import com.caito.authorizationserver.api.exceptions.customs.NotFoundException;
import com.caito.authorizationserver.api.models.responses.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

/**
 * @author claudio.vilas
 * date 12/2023
 * description handle para manejar error NotFoundException
 */

@RestControllerAdvice
@ResponseStatus(HttpStatus.NOT_FOUND)
public class NotFoundExceptionController {
    @ExceptionHandler(NotFoundException.class)
    protected ResponseEntity<ErrorResponse> notFoundExceptionHandler(NotFoundException e,
                                                                     HttpServletRequest request){
        var response = ErrorResponse.builder()
                .code(HttpStatus.NOT_FOUND.value())
                .status(HttpStatus.NOT_FOUND.name())
                .timestamp(LocalDateTime.now())
                .message(e.getMessage())
                .path(request.getRequestURI())
                .build();
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }
}
