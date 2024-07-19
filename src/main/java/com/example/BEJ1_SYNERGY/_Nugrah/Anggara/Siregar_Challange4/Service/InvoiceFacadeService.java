package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import java.util.UUID;

public interface InvoiceFacadeService {
    byte[] generateInvoiceService(UUID idUser,UUID idOrder);
}
