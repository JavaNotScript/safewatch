package com.safewatch.auth.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class UserDTO {
    private String email;
    private boolean isLocked;
    private boolean isEnabled;
    private boolean isCredentialExpired;
}
