package com.example.apiapplicaion.domain.repository;

import com.example.apiapplicaion.domain.model.security.Role;
import com.example.apiapplicaion.domain.model.security.RoleType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleType name);
}
