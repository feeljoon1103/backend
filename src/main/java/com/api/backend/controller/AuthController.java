package com.api.backend.controller;

import com.api.backend.exception.RefreshTokenException;
import com.api.backend.exception.RoleException;
import com.api.backend.jwt.JwtUtils;
import com.api.backend.modal.ERole;
import com.api.backend.modal.RefreshToken;
import com.api.backend.modal.Role;
import com.api.backend.modal.User;
import com.api.backend.payload.request.LoginRequest;
import com.api.backend.payload.request.RoleRequest;
import com.api.backend.payload.request.SignupRequest;
import com.api.backend.payload.request.TokenRefreshRequest;
import com.api.backend.payload.response.JWTResponse;
import com.api.backend.payload.response.MessageResponse;
import com.api.backend.payload.response.TokenRefreshResponse;
import com.api.backend.security.CustomUserDetails;
import com.api.backend.service.impl.RefreshTokenService;
import com.api.backend.service.impl.RoleService;
import com.api.backend.service.impl.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import springfox.documentation.annotations.ApiIgnore;
import static org.springframework.data.util.Optionals.ifPresentOrElse;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthController.class);

    UserService userService;

    RoleService roleService;

    RefreshTokenService refreshTokenService;

    AuthenticationManager authenticationManager;

    PasswordEncoder encoder;

    JwtUtils jwtUtils;

    @Autowired
    public AuthController(UserService userService, RoleService roleService, RefreshTokenService refreshTokenService,
                          AuthenticationManager authenticationManager, PasswordEncoder encoder, JwtUtils jwtUtils) {
        this.userService = userService;
        this.roleService = roleService;
        this.refreshTokenService = refreshTokenService;
        this.authenticationManager = authenticationManager;
        this.encoder = encoder;
        this.jwtUtils = jwtUtils;
    }

    @PostMapping("/addrole")
    public ResponseEntity<?> addRole(@RequestBody RoleRequest roleRequest) {

        String roleName = roleRequest.getRoleName();
        Role role = null;

        switch (roleName) {
            case "ROLE_ADMIN":

                role = new Role(ERole.ROLE_ADMIN);

                break;

            case "ROLE_MODERATOR":

                role = new Role(ERole.ROLE_MODERATOR);
                break;

            default:

                role = new Role(ERole.ROLE_USER);
                ;
        }

        roleService.saveRole(role);

        return ResponseEntity.badRequest().body(new MessageResponse("Role: " + roleName + " saved "));
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignupRequest signUpRequest) {

        LOGGER.info("AuthController | registerUser is started");

        String username = signUpRequest.getUsername();
        String email = signUpRequest.getEmail();
        String password = signUpRequest.getPassword();
        Set<String> strRoles = signUpRequest.getRoles();
        Set<Role> roles = new HashSet<>();


        if (userService.existsByUsername(username)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userService.existsByEmail(email)) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken!"));
        }

        User user = new User();
        user.setEmail(email);
        user.setUsername(username);
        user.setPassword(encoder.encode(password));


        if (strRoles != null) {
            strRoles.forEach(role -> {
                LOGGER.info("AuthController | registerUser | role : " + role);
                switch (role) {
                    case "ROLE_ADMIN":

                        Role adminRole = null;

                        if (roleService.findByName(ERole.ROLE_ADMIN).isPresent()) {
                            adminRole = new Role(ERole.ROLE_ADMIN);
                        } else {
                            adminRole = roleService.findByName(ERole.ROLE_ADMIN)
                                    .orElseThrow(() -> new RoleException("Error: Admin Role is not found."));
                        }

                        roles.add(adminRole);
                        break;

                    case "ROLE_MODERATOR":

                        Role moderatorRole = null;

                        if (roleService.findByName(ERole.ROLE_MODERATOR).isPresent()) {
                            moderatorRole = new Role(ERole.ROLE_MODERATOR);
                        } else {
                            moderatorRole = roleService.findByName(ERole.ROLE_MODERATOR)
                                    .orElseThrow(() -> new RoleException("Error: Moderator Role is not found."));
                        }

                        roles.add(moderatorRole);

                        break;

                    default:

                        Role userRole = null;

                        if (roleService.findByName(ERole.ROLE_USER).isPresent()) {
                            userRole = new Role(ERole.ROLE_USER);
                        } else {
                            userRole = roleService.findByName(ERole.ROLE_USER)
                                    .orElseThrow(() -> new RoleException("Error: User Role is not found."));
                        }

                        roles.add(userRole);

                }

            });
        } else {

           /* Role userRole = null;
            if (roleService.findTop1ByName(ERole.ROLE_USER).isPresent()) {
                userRole = new Role(ERole.ROLE_USER);
            } else {
                userRole = new Role(ERole.ROLE_USER);
            }

            roles.add(userRole);*/

            //roleService.findByName(ERole.ROLE_USER).ifPresent(roles::add, () -> roles.add(new Role(ERole.ROLE_USER)));

            Optional<Role> role = roleService.findTop1ByName(ERole.ROLE_USER);
            roles.add(role.get());
            //if (role.equals(ERole.ROLE_USER) || role.equals(ERole.ROLE_MODERATOR) || role.equals(ERole.ROLE_ADMIN)) {
            if (role.get().getName() == ERole.ROLE_USER || role.get().getName() == ERole.ROLE_MODERATOR || role.get().getName() == ERole.ROLE_ADMIN) {
                roles.add(role.get());

            } else {
                roles.add(new Role(ERole.ROLE_USER));
            }

        }

        roleService.saveRoles(roles);
        user.setRoles(roles);
        userService.saveUser(user);


        return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
    }

    /*@PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {

        LOGGER.info("AuthController | authenticateUser is started");

        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        LOGGER.info("AuthController | authenticateUser | username : " + username);
        LOGGER.info("AuthController | authenticateUser | password : " + password);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        LOGGER.info("AuthController | authenticateUser | usernamePasswordAuthenticationToken : " + usernamePasswordAuthenticationToken.toString());

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);

        LOGGER.info("AuthController | authenticateUser | jwt : " + jwt);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LOGGER.info("AuthController | authenticateUser | roles : " + roles.toString());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        LOGGER.info("AuthController | authenticateUser | refreshToken : " + refreshToken.toString());

        JWTResponse jwtResponse = new JWTResponse();
        jwtResponse.setEmail(userDetails.getEmail());
        jwtResponse.setUsername(userDetails.getUsername());
        jwtResponse.setId(userDetails.getId());
        jwtResponse.setToken(jwt);
        jwtResponse.setRefreshToken(refreshToken.getToken());
        jwtResponse.setRoles(roles);



        LOGGER.info("AuthController | authenticateUser | jwtResponse : " + jwtResponse.toString());

        //return ResponseEntity.ok(jwtResponse);
        LOGGER.info("JWT_TOKEN : " + jwt);
        return ResponseEntity.ok(jwt);
    }*/

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest, HttpServletResponse res) {

        LOGGER.info("AuthController | authenticateUser is started");

        String username = loginRequest.getUsername();
        String password = loginRequest.getPassword();

        LOGGER.info("AuthController | authenticateUser | username : " + username);
        LOGGER.info("AuthController | authenticateUser | password : " + password);

        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        LOGGER.info("AuthController | authenticateUser | usernamePasswordAuthenticationToken : " + usernamePasswordAuthenticationToken.toString());

        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateJwtToken(userDetails);

        LOGGER.info("AuthController | authenticateUser | jwt : " + jwt);

        List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LOGGER.info("AuthController | authenticateUser | roles : " + roles.toString());

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        LOGGER.info("AuthController | authenticateUser | refreshToken : " + refreshToken.toString());

        JWTResponse jwtResponse = new JWTResponse();
        jwtResponse.setEmail(userDetails.getEmail());
        jwtResponse.setUsername(userDetails.getUsername());
        jwtResponse.setId(userDetails.getId());
        jwtResponse.setToken(jwt);
        jwtResponse.setRefreshToken(refreshToken.getToken());
        jwtResponse.setRoles(roles);

        Cookie cookie = new Cookie("token", jwt);
        cookie.setHttpOnly(true);
        cookie.setPath("/");

        res.addCookie(cookie);

        LOGGER.info("AuthController | authenticateUser | jwtResponse : " + jwtResponse.toString());

        //return ResponseEntity.ok(jwtResponse);
        LOGGER.info("JWT_TOKEN : " + jwt);
        //return ResponseEntity.ok(jwt);
        return new ResponseEntity<>(jwtResponse, HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@ApiIgnore Principal principalUser) {

        LOGGER.info("AuthController | logoutUser is started");

        Object principal = ((UsernamePasswordAuthenticationToken) principalUser).getPrincipal();
        CustomUserDetails user = (CustomUserDetails) principal;

        int userId = user.getId();

        LOGGER.info("AuthController | logoutUser | userId : " + userId);

        int deletedValue = refreshTokenService.deleteByUserId(userId);

        if (deletedValue == 1) {
            return ResponseEntity.ok(new MessageResponse("Log out successful!"));
        } else {
            return ResponseEntity.ok(new MessageResponse("You're already logout"));
        }

    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {

        LOGGER.info("AuthController | refreshtoken is started");

        String requestRefreshToken = request.getRefreshToken();

        LOGGER.info("AuthController | refreshtoken | requestRefreshToken : " + requestRefreshToken);

        RefreshToken token = refreshTokenService.findByToken(requestRefreshToken)
                .orElseThrow(() -> new RefreshTokenException(requestRefreshToken + "Refresh token is not in database!"));

        LOGGER.info("AuthController | refreshtoken | token : " + token.toString());

        RefreshToken deletedToken = refreshTokenService.verifyExpiration(token);

        LOGGER.info("AuthController | refreshtoken | deletedToken : " + deletedToken.toString());

        User userRefreshToken = deletedToken.getUser();

        LOGGER.info("AuthController | refreshtoken | userRefreshToken : " + userRefreshToken.toString());

        String newToken = jwtUtils.generateTokenFromUsername(userRefreshToken.getUsername());

        LOGGER.info("AuthController | refreshtoken | newToken : " + newToken);

        return ResponseEntity.ok(new TokenRefreshResponse(newToken, requestRefreshToken));

    }

    @GetMapping("/check")
    public ResponseEntity check(@CookieValue(value = "token") String token) {

            if (token != null && jwtUtils.validateJwtToken(token)) {
                return new ResponseEntity<>(1, HttpStatus.OK);
            } else {

                return new ResponseEntity<>(0, HttpStatus.OK);
            }


    }
}
