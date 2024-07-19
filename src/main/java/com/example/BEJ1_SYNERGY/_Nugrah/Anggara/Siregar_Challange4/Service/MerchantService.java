package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Merchant;

import java.util.List;
import java.util.UUID;

public interface MerchantService {
    Merchant addingMerchant(Merchant merchant);
    Merchant editStatusMerchant(UUID id,boolean status);
    List<Merchant> getOpenMerchant();
    Merchant getMerchantById(UUID id);
}
