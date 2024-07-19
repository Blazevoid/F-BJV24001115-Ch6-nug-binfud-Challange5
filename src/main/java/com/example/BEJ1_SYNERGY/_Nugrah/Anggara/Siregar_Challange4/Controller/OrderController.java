package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Controller;


import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.OrderRequestDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.OrderResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Product;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account.User;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.ProductRepository;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.UserRepository;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.InvoiceFacadeService;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.OrderService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;
import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping(path = "/order")
public class OrderController {
    private final Logger LOG = LoggerFactory.getLogger(OrderController.class);
    @Autowired
    private OrderService orderService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private InvoiceFacadeService invoiceFacadeService;

    @Autowired
    ProductRepository productRepository;

    @PostMapping(value = "/add")
    @PreAuthorize("hasRole('ROLE_CUSTOMER')")
    public OrderResponseDto addOrder(@RequestBody OrderRequestDto orderRequestDto) throws ParseException {

        Optional<User> user = userRepository.findById(UUID.fromString(orderRequestDto.getIdUser()));
        Optional<Product> product = productRepository.findById(UUID.fromString(orderRequestDto.getIdProduct()));

        return orderService.createOrder(user.get(),product.get(), orderRequestDto.getAddress(), orderRequestDto.getQuantity());
    }

    @GetMapping(path = "/detail/{id}")
    @PreAuthorize("hasRole('ROLE_CUSTOMER')")
    ResponseEntity<Object> getOrder(@PathVariable String id){
        return new ResponseEntity<>(orderService.getOrderDetail(id), HttpStatus.OK);
    }

    @GetMapping(path = "/generate/{idUser}/{idOrder}")
    @PreAuthorize("hasRole('ROLE_CUSTOMER')")
    public ResponseEntity<Resource> generateInvoice(
            @PathVariable("idUser") String idUser,
            @PathVariable("idOrder") String idOrder){

        byte[] invoiceContent = invoiceFacadeService.generateInvoiceService(UUID.fromString(idUser),UUID.fromString(idOrder));

        ByteArrayResource resource = new ByteArrayResource(invoiceContent);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(resource.contentLength())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename("invoice binarfud.pdf")
                                .build()
                                .toString())
                .body(resource);

    }

}
