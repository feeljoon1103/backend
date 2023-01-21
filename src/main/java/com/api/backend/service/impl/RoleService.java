package com.api.backend.service.impl;

import com.api.backend.modal.ERole;
import com.api.backend.modal.Role;
import com.api.backend.repository.RoleRepository;
import com.api.backend.service.IRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class RoleService implements IRoleService {

    RoleRepository roleRepository;

    @Autowired
    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    @Override
    public Optional<Role> findByName(ERole name) {
        return roleRepository.findByName(name);
    }

    @Override
    public Optional<Role> findTop1ByName(ERole name) {
        return roleRepository.findTop1ByName(name);
    }

    public void saveRole(Role role){
        roleRepository.save(role);
    }

    public void saveRoles(Set<Role> roles){
        roleRepository.saveAll(roles);
    }


}
