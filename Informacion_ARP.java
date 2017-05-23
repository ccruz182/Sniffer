package sniffer_redes;

import org.jnetpcap.packet.JPacket;

public class Informacion_ARP {
    private JPacket paq;
    
    final int IPV4 = 2048;
    final int ARP = 2054;
    final int IPV6 = 34525;
    
    public Informacion_ARP(JPacket paquete) {
        this.paq = paquete;
    }
    
    public String getInformacionDetallada() {
        String texto = "\nEncabezado ARP\n\tTipo de Hardware: ";
        String aux, aux2;
        int hard_type = (paq.getUByte(14) * 256) + paq.getUByte(15);
        aux = hardwareTypeARP(hard_type);
        texto += aux;
        int prot_type = (paq.getUByte(16) * 256) + paq.getUByte(17);
        aux2 = Integer.toHexString(prot_type);
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0; i < tmp; i++) {
                aux2 = '0' + aux2;
            }
        }
        aux = protocolTypeARP(prot_type);
        texto += "\n\tTipo de Protocolo: " + aux + " (0x" + aux2 + ")";
        texto += "\n\tTamaño de Hardware: " + paq.getUByte(18) + "\n\tTamaño de Protocolo: " + paq.getUByte(19);
        int opcode = (paq.getUByte(20) * 256) + paq.getUByte(21);
        aux = opcodeARP(opcode);
        texto += "\n\tCódigo de Operación: " + aux + " (" + opcode + ")";        
        aux = "";
        for(int i = 22; i < 28; i++){
            aux += String.format("%02X", paq.getUByte(i)) + ":";                            
        }                        
        texto += "\n\tMAC del emisor: " + aux;
        texto += "\n\tIP del emisor: " + paq.getUByte(28) + "." + paq.getUByte(29) + "." + paq.getUByte(30) + "." + paq.getUByte(31);
        aux = "";
        for(int i = 32; i < 38; i++){
            aux += String.format("%02X", paq.getUByte(i)) + ":";                            
        }
        texto += "\n\tMAC del destinatario: " + aux;
        texto += "\n\tIP del destinatario: " + paq.getUByte(38) + "." + paq.getUByte(39) + "." + paq.getUByte(40) + "." + paq.getUByte(41);
        
        return texto;
    }
    
    private String hardwareTypeARP(int type) {
        String texto = "";
        switch(type) {
            case 0: texto = "Reservado"; break;
            case 1: texto = "Ethernet"; break;
            case 6: texto = "IEEE 802"; break;
            case 7: texto = "ARCNET"; break;
            case 15: texto = "Frame Relay"; break;
            case 16: texto = "ATM"; break;
            case 17: texto = "HDLC"; break;
            case 18: texto = "Canal de Fibra"; break;
            case 20: texto = "Linea Serial"; break;
            default: texto = "Otro"; break;
        }
        return texto;
    }
   
    private String protocolTypeARP(int type) {
        String texto = "";
        if(type == IPV4) {texto = "IPv4";}
        else if(type == IPV6) {texto = "IPv6";}
        else {texto = "Otro";}
        
        return texto;
    }
    
    private String opcodeARP(int opcode) {
        String texto = "";
        switch(opcode) {
            case 1: texto = "Solicitud ARP"; break;
            case 2: texto = "Respuesta ARP"; break;
            case 3: texto = "Solicitud RARP"; break;
            case 4: texto = "Respuesta RARP"; break;
            case 5: texto = "Solicitud DRARP"; break;
            case 6: texto = "Respuesta DRARP"; break;
            case 7: texto = "Error DRARP"; break;
            case 8: texto = "Solicitud InARP"; break;
            case 9: texto = "Respuesta InARP"; break;
            
        }
        return texto;
    }
}
