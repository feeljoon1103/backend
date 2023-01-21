package com.api.backend.service;

import com.api.backend.modal.ERole;
import com.api.backend.modal.Role;

import java.util.Optional;

public interface IRoleService {
    Optional<Role> findByName(ERole name);

    Optional<Role> findTop1ByName(ERole name);

}
