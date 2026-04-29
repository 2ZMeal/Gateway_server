package com.ezmeal.gateway.exception.code;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
    INTERNAL_ERROR("AUTH_000", HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error"),
    UNAUTHORIZED("AUTH_001", HttpStatus.UNAUTHORIZED, "Unauthorized Access"),
    FORBIDDEN("AUTH_002", HttpStatus.FORBIDDEN, "Forbidden"),;

    private final String code;
    private final HttpStatus status;
    private final String message;
}
