package sniffer_redes;

public class Sniffer_Redes {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        String tempo_1;
        int valor = 14;
        if(String.valueOf(valor).length() == 1) {
                tempo_1 = '0' + String.valueOf(valor);               
        } else {
             tempo_1 = String.valueOf(Integer.valueOf(String.valueOf(valor), 16));
        }
        
        System.out.println("Tempo: " + tempo_1);
    }
    
}
