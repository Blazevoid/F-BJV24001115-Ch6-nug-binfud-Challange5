package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.UUID;

@Data
@Setter
@Getter
public class OrderResponseDto {
    private UUID id;
    private Date order_time;
    private String destination_address;
    private UUID user_id;
    private boolean completed;
}
