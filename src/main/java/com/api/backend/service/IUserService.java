package com.api.backend.service;

import com.api.backend.modal.User;

import java.util.Optional;

public interface IUserService {

    void saveUser(User user);
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    User findById(int userId);
}
