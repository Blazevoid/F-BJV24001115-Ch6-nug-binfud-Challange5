package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.email;

import java.util.concurrent.CompletableFuture;

public interface OtpService {
    String generateOTP(String accountNumber);
    CompletableFuture<Boolean> sendOTPByEmail(String email, String name, String accountNumber, String otp);
    boolean validateOTP(String accountNumber, String otp);
}
