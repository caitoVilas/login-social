package com.caito.authorizationserver.api.models.responses;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.time.LocalDateTime;

/**
 * @author claudio.vilas
 * date 12/2023
 * description modelo para representar error genericos en los respuestas
 */

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ErrorResponse implements Serializable {
    private Integer code;
    private String status;
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "dd-MM-yyyy HH:mm:ss")
    private LocalDateTime timestamp;
    private String message;
    private String path;
}
