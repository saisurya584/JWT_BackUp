package com.Jwt.controller;

import com.Jwt.Service.JwtService;
import com.Jwt.entity.AuthRequest;
import com.Jwt.entity.User;
import com.Jwt.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api")
public class UserController {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtService jwtService;
    @PostMapping("save")
    public ResponseEntity<User> saveRecord(@RequestBody User user)
    {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return new ResponseEntity<>(userRepository.save(user), HttpStatus.CREATED);
    }
   @GetMapping("/records")
   @PreAuthorize("hasAuthority('ADMIN')")
    public List<User> getAllRecords()
   {
       List<User> all = userRepository.findAll();
       return all;
   }
   @PostMapping("/authenicate")
    public String AuthenicateAndGenerateToken(@RequestBody AuthRequest authRequest)
    {
        Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUserName(), authRequest.getPassword()));
        if(authenticate.isAuthenticated()){
        return jwtService.generateToken(authRequest.getUserName());}
        else {
            throw new UsernameNotFoundException("user not found");
        }
    }
}
