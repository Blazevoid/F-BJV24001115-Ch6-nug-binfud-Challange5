package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.OrderDetailResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.OrderResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Order;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.OrderDetail;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Product;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account.User;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.OrderDetailRepository;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;


@Service
public class OrderServiceImpl implements OrderService {
    @Autowired
    private OrderRepository orderRepository;

    @Autowired
    OrderDetailRepository orderDetailRepository;

    @Override
    public OrderResponseDto createOrder(User user, Product product, String address, int quantity) throws ParseException {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

        Order dataOrder = new Order();
        dataOrder.setUser(user);
        dataOrder.setOrder_time(sdf.parse(LocalDate.now().toString()));
        dataOrder.setDestination_address(address);
        dataOrder.setCompleted(false);
        Order order = orderRepository.save(dataOrder);

        OrderDetail orderDetail = new OrderDetail();
        orderDetail.setOrder(order);
        orderDetail.setProduct(product);
        orderDetail.setQuantity(quantity);
        orderDetail.setTotal_price(quantity * product.getPrice());

        orderDetailRepository.save(orderDetail);
        order.setCompleted(true);
        Order data = orderRepository.save(order);

        OrderResponseDto orderResponseDto = new OrderResponseDto();
        orderResponseDto.setId(data.getId());
        orderResponseDto.setOrder_time(data.getOrder_time());
        orderResponseDto.setDestination_address(data.getDestination_address());
        orderResponseDto.setUser_id(data.getUser().getId());
        orderResponseDto.setCompleted(data.isCompleted());
        return orderResponseDto;
    }

    @Override
    public List<OrderDetailResponseDto> getOrderDetail(String id) {
        UUID uuid = UUID.fromString(id);

        List<OrderDetail> orderDetails = orderDetailRepository.findByOrder(uuid);
        if (orderDetails == null || orderDetails.isEmpty()) {
            return Collections.emptyList();
        }

        return orderDetails.stream()
                .map(order -> new OrderDetailResponseDto(order.getId(), order.getOrder().getOrder_time(),
                        order.getProduct().getProductName(), order.getQuantity(), order.getTotal_price()))
                .collect(Collectors.toList());
    }
}

