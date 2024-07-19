package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto;


import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@Data
public class UserRequestDto {
    private String username;
    private String email;
    private String password;
}
