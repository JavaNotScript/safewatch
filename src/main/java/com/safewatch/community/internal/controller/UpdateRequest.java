package com.safewatch.community.internal.controller;

public record UpdateRequest(
        String communityName,
        String communityNewName,
        String visibility,
        String audience
) {
}
