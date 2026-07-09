package com.safewatch.auth.internal.controller;

import com.safewatch.auth.internal.dto.CurrentUserDTO;
import com.safewatch.auth.api.AuthFacade;
import com.safewatch.auth.internal.util.login.*;
import com.safewatch.auth.internal.util.register.RegistrationRequest;
import com.safewatch.auth.internal.util.register.VerifyRequest;
import com.safewatch.auth.internal.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Duration;
import java.util.Optional;


@RestController
@RequestMapping("/api/v1/auth")
@Validated
public class AuthController {
    private final AuthService authService;
    private final AuthFacade authFacade;
    private final boolean isSecure;
    private final String path;
    private final String site;

    public AuthController(AuthService authService, AuthFacade authFacade, @Value("${app.cookie.secure}") boolean isSecure, @Value("${app.cookie.path}") String path, @Value("${app.cookie.samesite}") String site) {
        this.authService = authService;
        this.authFacade = authFacade;
        this.isSecure = isSecure;
        this.path = path;
        this.site = site;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegistrationRequest registrationRequest) {
        return ResponseEntity.ok(authService.register(registrationRequest));
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyToken(@Valid @RequestBody VerifyRequest verifyRequest) {
        authService.verifyToken(verifyRequest.token());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        var user = authFacade.findUser(request.email());

        String userAgent = Optional.ofNullable(servletRequest.getHeader("User-Agent")).orElse("unknown");

        String ip = Optional.ofNullable(servletRequest.getHeader("X-Forwarded-For"))
                .map(v -> v.split(",")[0].trim())
                .orElse(servletRequest.getRemoteAddr());

        var result = authService.login(request.email(), request.password(), user.getUserId(), userAgent, ip);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", result.refreshToken())
                .httpOnly(true)
                .secure(isSecure) //local development only, production set = true
                .sameSite(site)
                .path(path)
                .maxAge(Duration.ofDays(30))
                .build();

        servletResponse.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());


        return ResponseEntity.ok(new LoginResponse(result.accessToken()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        if (refreshToken == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        String userAgent = Optional.ofNullable(servletRequest.getHeader("User-Agent")).orElse("unknown");
        String ip = Optional.ofNullable(servletRequest.getHeader("X-Forwarded-For"))
                .map(v -> v.split(",")[0].trim())
                .orElse(servletRequest.getRemoteAddr());

        var result = authService.refresh(refreshToken, userAgent, ip);

        ResponseCookie cookie = ResponseCookie.from("refreshToken", result.refreshToken())
                .httpOnly(true)
                .secure(isSecure)
                .sameSite(site)
                .path(path)
                .maxAge(Duration.ofDays(30))
                .build();

        servletResponse.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(new LoginResponse(result.accessToken()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refreshToken") String refreshToken) {
        if (refreshToken != null) {
            authService.logout(refreshToken);
        }

        return ResponseEntity.ok().build();
    }

    @PutMapping("/update/details")
    public ResponseEntity<CurrentUserDTO> updateDetails(Authentication authentication, @RequestBody @Valid UserDetailsUpdateRequest updateRequest) {
        String email = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(authService.updateDetails(email, updateRequest));
    }

    @PutMapping("/update/password")
    public ResponseEntity<String> updatePassword(Authentication authentication, @RequestBody @Valid PasswordUpdateRequest updateRequest) {
        String email = authFacade.extractEmail(authentication);
        return ResponseEntity.ok(authService.updatePassword(email, updateRequest));
    }

    @PostMapping("/forgot/password")
    public ResponseEntity<?> forgotPassword(@RequestBody @Valid ResetPasswordRequest passwordRequest) {
        authService.RequestPasswordReset(passwordRequest.email());
        return ResponseEntity.ok().build();
    }

    @PutMapping("/verify")
    public ResponseEntity<?> resetPassword(@RequestBody @Valid PasswordResetRequest resetRequest) {
        authService.passwordReset(resetRequest.token(), resetRequest.newPassword(), resetRequest.confirmPassword());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/deactivate-account/{password}")
    public ResponseEntity<Void> deActivateAccount(Authentication authentication, @RequestPart String password) {
        Long userId = authFacade.extractUserId(authentication);
        authService.deactivateAccount(userId, password);
        return ResponseEntity.ok().build();
    }
}
