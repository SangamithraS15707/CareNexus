package com.carenexus.auth_service.dto;

public record LoginResponse(
        String accessToken,
        String tokenType
) {}