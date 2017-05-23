package sniffer_redes;

import org.jnetpcap.packet.JPacket;

public class Aux_Live {
    private JPacket paquete;
    
    public Aux_Live(JPacket paquete) {
        this.paquete = paquete;
    }
    
    public int getTipo(){
        int tipo = (paquete.getUByte(12) * 256 ) + (paquete.getUByte(13));
        
        return tipo;
    }
    
    public String getTipo_byte1(){
        String tipo_byte1;
        if(String.valueOf(paquete.getUByte(12)).length() == 1) {
                tipo_byte1 = '0' + String.valueOf(paquete.getUByte(12));               
            } 
        else {
                tipo_byte1 = Integer.toHexString(paquete.getUByte(12));
        }
        return tipo_byte1;
    }
    
    public String getTipo_byte2(){
        String tipo_byte2;
        if(String.valueOf(paquete.getUByte(13)).length() == 1) {
                tipo_byte2 = '0' + String.valueOf(paquete.getUByte(13));               
            } 
        else{
                tipo_byte2 = Integer.toHexString(paquete.getUByte(13));
        }
        return tipo_byte2;
    }
            
    public String getMacd(){
        String macd = "";
        for(int i = 0; i < 6; i++){
            macd = macd.concat(String.format("%02X",paquete.getUByte(i)));
            macd = macd.concat(" ");                
        }
        return macd;    
    }
    
    public String getMaco(){
        String maco = "";
        for(int i = 6; i < 12; i++){
                maco = maco.concat(String.format("%02X",paquete.getUByte(i)));
                maco = maco.concat(" ");                
        }
        return maco;
    }
}