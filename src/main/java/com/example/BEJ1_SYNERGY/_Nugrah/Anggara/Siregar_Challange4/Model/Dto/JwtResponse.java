package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class JwtResponse {
    private String jwt;
    private String username;
    private List<String> roles;
}
