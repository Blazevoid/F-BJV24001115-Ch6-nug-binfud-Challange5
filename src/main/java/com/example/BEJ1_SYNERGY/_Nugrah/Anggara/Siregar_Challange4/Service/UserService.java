package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.UserRequestDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.UserResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account.User;

import java.util.Map;
import java.util.UUID;

public interface UserService {

    User getUserById(UUID userID);
    UserResponseDto addUser(UserRequestDto userRequestDto);
    Map<String,Object> updateUser(UserRequestDto userRequestDto, UUID id);
    Map<String,Object> deleteUser(UUID id);

    void createUserPostLogin(String email, String email1);
    User getByUsername(String username);
}
