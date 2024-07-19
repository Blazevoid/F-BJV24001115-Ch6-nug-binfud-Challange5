package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;
import java.util.UUID;

@Entity
@Setter
@Getter
@Accessors(chain = true)
@Table(name = "product")
public class Product{
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "product_name")
    private String productName;

    private double price;
    @ManyToOne
    @JoinColumn(name = "id_merchant")
    private Merchant merchant;
}
