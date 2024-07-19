package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import java.util.UUID;

@ResponseStatus(value = HttpStatus.NOT_FOUND,reason = "tidak ditemukan")
public class NotFoundException extends RuntimeException{
    public NotFoundException(UUID uuid){
        super(uuid.toString() + " tidak ditemukan");
    }
}
