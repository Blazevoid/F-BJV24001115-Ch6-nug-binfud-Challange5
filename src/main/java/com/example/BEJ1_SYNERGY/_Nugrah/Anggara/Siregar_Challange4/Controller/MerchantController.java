package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Controller;


import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Dto.MerchantResponseDto;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Model.Merchant;
import com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4.Service.MerchantService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping(path = "/merchant")
public class MerchantController {
    @Autowired
    private MerchantService merchantService;
    @Autowired
    private ModelMapper modelMapper;

    @GetMapping(path = "/open-merchant")
    public ResponseEntity<Map<String,Object>> getMerchant(){
        Map<String,Object> body = new HashMap<>();
        List<MerchantResponseDto> merchResponseDto = merchantService.getOpenMerchant().stream()
                        .map(merchant -> this.modelMapper.map(merchant,MerchantResponseDto.class))
                                .toList();

        body.put("status code",HttpStatus.OK.value());
        body.put("message",HttpStatus.OK.getReasonPhrase());
        body.put("data",merchResponseDto);

        return new ResponseEntity<>(body,HttpStatus.OK);
    }


    @PutMapping(path = "/status/{id}/{status}")
    public ResponseEntity<Map<String,Object>> editStatusMerchant(@PathVariable("id") String id,@PathVariable("status") String status){
        Map<String,Object> body = new HashMap<>();
        Merchant merchant = merchantService.editStatusMerchant(UUID.fromString(id),Boolean.parseBoolean(status));
        if (merchant == null){
            body.put("status code",HttpStatus.NOT_FOUND.value());
            body.put("message",HttpStatus.NOT_FOUND.getReasonPhrase());
            body.put("data",null);
            return new ResponseEntity<>(body,HttpStatus.NOT_FOUND);
        }
        MerchantResponseDto merchantResponseDto = this.modelMapper.map(merchant, MerchantResponseDto.class);
        body.put("message",HttpStatus.OK.getReasonPhrase());
        body.put("status code",HttpStatus.OK.value());
        body.put("data",merchantResponseDto);

        return new ResponseEntity<>(body,HttpStatus.OK);
    }


    @PostMapping(path = "/daftar-merchant")
    public ResponseEntity<MerchantResponseDto> addMerchant(@ModelAttribute Merchant merchant){
        MerchantResponseDto merchantResponseDto = this.modelMapper.map(
                merchantService.addingMerchant(merchant),
                MerchantResponseDto.class);

        return new ResponseEntity<>(merchantResponseDto,HttpStatus.OK);
    }


    @GetMapping(path = "/{id}")
    public ResponseEntity<Map<String,Object>> getMerchantById(@PathVariable String id){
        Merchant merchant = merchantService.getMerchantById(UUID.fromString(id));

        Map<String,Object> body= new HashMap<>();

        if (merchant == null){
            body.put("status code", HttpStatus.NOT_FOUND.value());
            body.put("message",HttpStatus.NOT_FOUND.getReasonPhrase());
            body.put("data",null);
            return new ResponseEntity<>(body,HttpStatus.NOT_FOUND);
        }

        MerchantResponseDto merchResponseDto = this.modelMapper.map(merchant,MerchantResponseDto.class);
        body.put("status code",HttpStatus.OK.value());
        body.put("message",HttpStatus.OK.getReasonPhrase());
        body.put("data",merchResponseDto);

        return new ResponseEntity<>(body,HttpStatus.OK);
    }

}
