package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service;

import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.InvoiceResponse;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.OrderDetailResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.account.User;
import net.sf.jasperreports.engine.*;
import net.sf.jasperreports.engine.data.JRBeanCollectionDataSource;
import net.sf.jasperreports.engine.util.JRLoader;
import net.sf.jasperreports.engine.util.JRSaver;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class InvoiceFacadeServiceImpl implements InvoiceFacadeService {
    @Autowired
    private UserService userService;

    @Autowired
    private ModelMapper mapper;
    @Autowired
    private OrderService orderService;


    @Override
    public byte[] generateInvoiceService(UUID idUser,UUID idOrder) {

        List<OrderDetailResponseDto> orderResponseDto = orderService.getOrderDetail(idOrder.toString());
        User user = userService.getUserById(idUser);

        List<InvoiceResponse> invoiceResponses = orderResponseDto.stream()
                .map(order -> this.mapper.map(order,InvoiceResponse.class))
                .toList();

        Map<String,Object> objectUser = new HashMap<>();
        objectUser.put("username",user.getUsername());
        objectUser.put("email",user.getEmail_address());

        JasperReport jasperReport;

        try {
            jasperReport = (JasperReport) JRLoader
                    .loadObject(ResourceUtils.getFile("report.jasper"));
        } catch (JRException | FileNotFoundException e) {
            try {
                File file = ResourceUtils.getFile("classpath:jasper/report.jrxml");
                jasperReport = JasperCompileManager.compileReport(file.getAbsolutePath());
                JRSaver.saveObject(jasperReport, "report.jasper");
            } catch (FileNotFoundException | JRException ex) {
                throw new RuntimeException(ex);
            }
        }

        JRBeanCollectionDataSource dataSource = new JRBeanCollectionDataSource(invoiceResponses);


        JasperPrint jasperPrint;
        byte[] reportContent;
        try {
            jasperPrint = JasperFillManager.fillReport(jasperReport, objectUser, dataSource);
            reportContent = JasperExportManager.exportReportToPdf(jasperPrint);
        } catch (JRException e) {
            e.printStackTrace();
            throw  new RuntimeException();
        }

        return reportContent;
    }
}
