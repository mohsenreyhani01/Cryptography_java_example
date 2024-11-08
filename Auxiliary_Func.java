

/************************************************
 *               Mohsen Reyhani                 *
 *                 August 2024                  *
 *   Twitter: https://x.com/mohsenreyhani01     *
 *   Tel: https://t.me/exciton_missile_program  *
 *   Blog: https://mreyhani.wordpress.com       *
 *   Email: mohsen0reyhani@gmail.com            *
 *   Copyright © 2024 Mohsen Reyhani            *
 *          All rights reserved.                *
 ************************************************/


import static android.content.Context.INPUT_METHOD_SERVICE;

import android.app.Activity;
import android.content.Context;
import android.view.inputmethod.InputMethodManager;
import android.view.inputmethod.InputMethodSubtype;
import androidx.annotation.NonNull;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Auxiliary_Func {


    private final static char[] _null = {'N','U','L','L'};



   public static byte[] chars_to_bytes(char[] chars) {

        CharBuffer charBuffer = CharBuffer.wrap(chars);
       Charset charset = StandardCharsets.UTF_8;

       ByteBuffer byteBuffer = charset.encode(charBuffer);
     

       byte[] bytes = byteBuffer.array();
    //    Arrays.fill(byteBuffer.array(), (byte) 0);
        return bytes;
    }



    public static char[] bytes_to_chars(byte[] byteArray){
        ByteBuffer buffer = ByteBuffer.wrap(byteArray);
        CharBuffer charBuffer = StandardCharsets.UTF_8.decode(buffer);

        int i = charBuffer.remaining();

        while (i >= 0) {

            if(charBuffer.charAt(i-1) != '\u0000') {

                break;
            }
                --i;
        }

        if(i>0)
        {
        char[] charArray = new char[i];
        charBuffer.get(charArray, 0, i);

        return charArray;

        } else return _null;
    }


}
