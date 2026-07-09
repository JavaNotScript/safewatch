package com.safewatch.auth.internal.repo;

import com.safewatch.auth.internal.domain.RoleType;
import com.safewatch.auth.internal.domain.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<UserRole, Long> {
    Optional<UserRole> findByRoleName(RoleType roleType);
}
