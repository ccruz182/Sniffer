package sniffer_redes;

public class Trama {
    private String macd;
    private String maco;   
    private int longitud;
    private String tipo_byte1;
    private String tipo_byte2;
    private int tipo;

    public String getMacd() {
        return macd;
    }

    public void setMacd(String macd) {
        this.macd = macd;
    }

    public String getMaco() {
        return maco;
    }

    public void setMaco(String maco) {
        this.maco = maco;
    }

    public int getLongitud() {
        return longitud;
    }

    public void setLongitud(int longitud) {
        this.longitud = longitud;
    }

    public String getTipo_byte1() {
        return tipo_byte1;
    }

    public void setTipo_byte1(String tipo_byte1) {
        this.tipo_byte1 = tipo_byte1;
    }

    public String getTipo_byte2() {
        return tipo_byte2;
    }

    public void setTipo_byte2(String tipo_byte2) {
        this.tipo_byte2 = tipo_byte2;
    }

    public int getTipo() {
        return tipo;
    }

    public void setTipo(int tipo) {
        this.tipo = tipo;
    }
         
    
}
