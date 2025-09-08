package com.chatify.app.common.util;


import com.chatify.app.core.auth.domain.Provider;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class StringToProviderConverter implements Converter<String, Provider> {

    @Override
    public Provider convert(String source){
        try{
            return Provider.valueOf(source.toUpperCase());
        }catch(IllegalArgumentException e){
            return null;
        }
    }
}
