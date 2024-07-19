package com.example.BEJ1_SYNERGY._Nugrah.Anggara.Siregar_Challange4;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class Bej1Synergy7NugrahAnggaraSiregarChallange4Application {

	public static void main(String[] args) {
		SpringApplication.run(Bej1Synergy7NugrahAnggaraSiregarChallange4Application.class, args);
	}

	@Bean
	public ModelMapper modelMapper(){
		return new ModelMapper();
	}

	@Bean
	public OpenAPI customApi(){
		return new OpenAPI().info(new Info().title("API BINARFUD")
				.description("API BINARFUD Yang DIbuat Untuk Memenuhi Challange"));
	}
}
