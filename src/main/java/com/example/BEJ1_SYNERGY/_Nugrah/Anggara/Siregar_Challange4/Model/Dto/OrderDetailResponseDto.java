package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

@AllArgsConstructor
@Data
public class OrderDetailResponseDto {

    private UUID idOrder;
    private Date orderTime;
    private String productName;
    private int quantity;
    private double totalPrice;
}
