package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Controller;


import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.JwtResponse;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.LoginRequestDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.UserRequestDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.UserResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.UserService;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account.UserDetailsImpl;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.account.jwt.JwtUtils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;


@RestController
@RequestMapping(path = "/user")
public class UserController {
    @Autowired
    private UserService userService;
    @Autowired
    private ModelMapper mapper;

    @Autowired
    JwtUtils jwtUtils;

    @Autowired
    AuthenticationManager authenticationManager;

    @PostMapping(path = "/registrasi")
    public ResponseEntity<UserResponseDto> addUser(@ModelAttribute UserRequestDto user){
        return new ResponseEntity<>(userService.addUser(user),HttpStatus.OK);
    }

    @PutMapping(path = "/{id}")
    @PreAuthorize("hasRole('ROLE_CUSTOMER')")
    public ResponseEntity<Object> updateUser(@PathVariable("id") String id,
                                                      @ModelAttribute UserRequestDto userRequestDto){
        return new ResponseEntity<>(userService.updateUser(userRequestDto,UUID.fromString(id)),HttpStatus.OK);
    }

    @DeleteMapping(path = "/delete/{id}")

    public ResponseEntity<Object> deleteUser(@PathVariable String id){
        Map<String,Object> body = new HashMap<>();
        if (userService.getUserById(UUID.fromString(id)) == null){
            body.put("statuscode",HttpStatus.NOT_FOUND.value());
            body.put("message",HttpStatus.NOT_FOUND.getReasonPhrase());
            return new ResponseEntity<>(body,HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity<>(
                userService.deleteUser(UUID.fromString(id)),
                HttpStatus.OK
        );
    }


    @PostMapping(path = "/login")
    public ResponseEntity<Object> loginAuth(@ModelAttribute LoginRequestDto loginRequest){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(),loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Map<String,Object> response = new HashMap<>();
        response.put("status","success");

        JwtResponse jwtResponse = new JwtResponse(jwt,userDetails.getUsername(),roles);
        Map<String,Object> data = new HashMap<>();
        data.put("jwt",jwtResponse);
        response.put("data",data);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }


    @GetMapping("/oauth2/success")
    public ResponseEntity<Map<String, Object>> googleLoginSuccess(Authentication authentication) {
        // Create a new Principal object with modified authorities
        OidcUser oidcUser = (OidcUser) authentication.getPrincipal();
        Collection<GrantedAuthority> authorities = new ArrayList<>(oidcUser.getAuthorities());
        authorities.add(new SimpleGrantedAuthority("ROLE_USER")); // TODO: fix it. Get it from DB

        UserDetailsImpl modifiedUserDetails = UserDetailsImpl.build(oidcUser);
        OidcUser modifiedOidcUser = new DefaultOidcUser(authorities, oidcUser.getIdToken(), oidcUser.getUserInfo());

        // Create a new Authentication object with the modified Principal
        Authentication modifiedAuthentication = new UsernamePasswordAuthenticationToken(
                modifiedOidcUser,
                oidcUser.getIdToken(),
                authorities
        );

        // Generate token using the modified authentication
        String jwt = jwtUtils.generateToken(modifiedAuthentication);

        // Extract user details from the modified authentication
        List<String> roles = modifiedAuthentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        // Prepare response
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        Map<String, Object> data = new HashMap<>();
        JwtResponse jwtResponse = new JwtResponse(jwt, modifiedUserDetails.getUsername(), roles);
        data.put("jwt", jwtResponse);
        response.put("data", data);

        return new ResponseEntity<>(response, HttpStatus.CREATED);

    }
}
