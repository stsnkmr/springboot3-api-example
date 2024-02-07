package com.example.apiapplicaion.presentation.controller;

import com.example.apiapplicaion.domain.model.security.Role;
import com.example.apiapplicaion.domain.model.security.User;
import com.example.apiapplicaion.domain.repository.RoleRepository;
import com.example.apiapplicaion.domain.repository.UserRepository;
import com.example.apiapplicaion.security.jwt.JwtUtils;
import com.example.apiapplicaion.security.service.UserDetailsImpl;
import com.example.apiapplication.presentation.openapi.api.AuthenticationApi;
import com.example.apiapplication.presentation.openapi.model.OpenApiJwtResponse;
import com.example.apiapplication.presentation.openapi.model.OpenApiLoginRequest;
import com.example.apiapplication.presentation.openapi.model.OpenApiMessageResponse;
import com.example.apiapplication.presentation.openapi.model.OpenApiSignupRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Controller
@RequiredArgsConstructor
public class AuthenticationController implements AuthenticationApi {
    private final AuthenticationManager authenticationManager;

    private final UserRepository userRepository;

    private final RoleRepository roleRepository;

    private final PasswordEncoder encoder;

    private final JwtUtils jwtUtils;


    /**
     * @param openApiLoginRequest ログイン情報 (required)
     * @return
     */
    @Override
    public ResponseEntity<OpenApiJwtResponse> login(OpenApiLoginRequest openApiLoginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(openApiLoginRequest.getUsername(), openApiLoginRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = jwtUtils.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());

        return ResponseEntity.ok(
                new OpenApiJwtResponse()
                        .id(userDetails.getId())
                        .username(userDetails.getUsername())
                        .email(userDetails.getEmail())
                        .token(jwt)
                        .roles(roles));
    }

    /**
     * @param openApiSignupRequest サインアップ情報 (required)
     * @return
     */
    @Override
    public ResponseEntity<OpenApiMessageResponse> signup(OpenApiSignupRequest openApiSignupRequest) {
        if (userRepository.existsByUsername(openApiSignupRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new OpenApiMessageResponse().message("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(openApiSignupRequest.getEmail())) {
            return ResponseEntity
                    .badRequest()
                    .body(new OpenApiMessageResponse().message("Error: Email is already in use!"));
        }

        // Create new user's account
        User user = new User(openApiSignupRequest.getUsername(),
                openApiSignupRequest.getEmail(),
                encoder.encode(openApiSignupRequest.getPassword()));

        Set<String> strRoles = new HashSet<>(openApiSignupRequest.getRole());
        Set<Role> roles = new HashSet<>();

//        strRoles.forEach(role -> {
//            switch (role) {
//                case "admin":
//                    Role adminRole = roleRepository.findByName(RoleType.ROLE_ADMIN)
//                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                    roles.add(adminRole);
//                    break;
//                case "mod":
//                    Role modRole = roleRepository.findByName(RoleType.ROLE_MODERATOR)
//                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                    roles.add(modRole);
//
//                    break;
//                default:
//                    Role userRole = roleRepository.findByName(RoleType.ROLE_USER)
//                            .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
//                    roles.add(userRole);
//            }
//        });

//        user.setRoles();
        userRepository.save(user);

        return ResponseEntity.ok(new OpenApiMessageResponse().message("User registered successfully!"));
    }
}
