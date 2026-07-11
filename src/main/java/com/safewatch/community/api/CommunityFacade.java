package com.safewatch.community.api;

import com.safewatch.community.internal.dto.CommunityDTO;

public interface CommunityFacade {
    CommunityDTO findByCommunityName(String communityName);
    CommunityDTO updateCommunityStatus(String communityName);
}
