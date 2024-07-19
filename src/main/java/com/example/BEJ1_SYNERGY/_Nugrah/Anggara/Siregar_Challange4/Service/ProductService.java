package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Product;
import org.springframework.data.domain.Page;


import java.util.List;
import java.util.UUID;

public interface ProductService {
    Product updateProduct(UUID id,Product product);
    boolean deleteProduct(UUID id);
    Product addProduct(Product product);
    List<Product> getProduct();

    Page<Product> getProductPagination(String i, String e);
}
