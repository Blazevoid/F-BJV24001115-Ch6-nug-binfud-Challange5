package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Product;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.ProductRepository;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.exception.NotFoundException;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.exception.ProductException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;


@Service
public class ProductServiceImpl implements ProductService{
    @Autowired
    ProductRepository productRepository;

    private final Logger LOG = LoggerFactory.getLogger(ProductServiceImpl.class);

    @Override
    public Product updateProduct(UUID id,Product product) {
        Product productOld = getProductById(id);
        if (productOld == null){
            LOG.error("Product Tidak Ditemukan");
            throw new ProductException("Product Tidak Ditemukan");
        }

        productOld.setProductName(product.getProductName())
                .setMerchant(product.getMerchant())
                .setPrice(product.getPrice());

        return productRepository.save(productOld);
    }

    @Override
    public boolean deleteProduct(UUID id) {
        Product product = getProductById(id);
        if (product == null){
            throw new NotFoundException(id);
        }

        productRepository.deleteById(id);

        return true;
    }

    @Override
    public Product addProduct(Product product) {
        if (product == null){
            throw new ProductException("Data Null");
        }

        return productRepository.save(product);
    }

    @Override
    public List<Product> getProduct() {
        return productRepository.findAll();
    }

    @Override
    public Page<Product> getProductPagination(String i, String e) {
        int init = Integer.parseInt(i);
        int end = Integer.parseInt(e);
        return productRepository.findAll(PageRequest.of(init,end));
    }


    public Product getProductById(UUID id){
        Optional<Product> product = productRepository.findById(id);
        return product.orElse(null);
    }


}
