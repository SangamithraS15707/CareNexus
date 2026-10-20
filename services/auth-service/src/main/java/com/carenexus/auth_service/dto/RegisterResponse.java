package com.carenexus.auth_service.dto;

public record RegisterResponse(
        Long id,
        String fullName,
        String email,
        String role
) {}
