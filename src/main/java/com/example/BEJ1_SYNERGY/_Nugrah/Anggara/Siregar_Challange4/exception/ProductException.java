package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.exception;


import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.NO_CONTENT,reason = "Null")
public class ProductException extends RuntimeException{
    public ProductException(String message){
        super(message);
    }
}
