package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Merchant;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.MerchantRepository;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.exception.NotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class MerchantServiceImpl implements MerchantService{
    @Autowired
    MerchantRepository merchantRepository;
    private final Logger LOG = LoggerFactory.getLogger(MerchantServiceImpl.class);
    @Override
    public Merchant addingMerchant(Merchant merchant) {
        return merchantRepository.save(merchant);
    }

    @Override
    public Merchant editStatusMerchant(UUID id, boolean status) {
        Merchant merchant = getMerchantById(id);
        if (merchant == null){
            LOG.error(id + " Not Found");
            return null;
        }

        merchant.setOpen(status);
        return merchantRepository.save(merchant);
    }

    @Override
    public List<Merchant> getOpenMerchant() {
        return merchantRepository.findByOpen(true);
    }


    public Merchant getMerchantById(UUID id){
        Optional<Merchant> merchant = merchantRepository.findById(id);
        LOG.info("data merchant ", merchant);
        return merchant.orElse(null);
    }
}
