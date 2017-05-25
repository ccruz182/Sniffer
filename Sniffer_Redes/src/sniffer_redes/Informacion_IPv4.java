package sniffer_redes;

import org.jnetpcap.packet.JPacket;

public class Informacion_IPv4 {
    private JPacket paq;
    public Informacion_IPv4(JPacket paquete) {
        this.paq = paquete;
    }
    
    public String getInformacionDetallada() {
        String texto = "\nEncabezado IP\n";
        String tempo;
        int version = paq.getUByte(14) >> 4;
        texto += "\tVersión:\t" + version;
        int hlen = (paq.getUByte(14) & 15) * 4;
        texto += "\n\tHLEN:\t" + hlen + " bytes";
        int dsf = paq.getUByte(15);
        if(String.valueOf(dsf).length() == 1) {
            tempo = '0' + String.valueOf(dsf);               
        } else {
            tempo = Integer.toHexString(dsf);
        }
        texto += "\n\tTipo de Servicio: 0x" + tempo;
        String s_dsf = Integer.toBinaryString(dsf);
        if(s_dsf.length() != 8) { //No cuenta los ceros al inicio
            s_dsf = fillZ(s_dsf);
        }
        tempo = precedenciaIPv4(s_dsf.substring(0, 3));        
        texto += "\n\t\tPrecedencia: " + tempo;
        tempo = caracServIPv4(s_dsf.substring(3));
        texto += "\n\t\tCaracteristicas: " + tempo;
        int l_tot = (paq.getUByte(16) * 256) + paq.getUByte(17);
        texto += "\n\tLongitud Total: " + l_tot;
        int id = (paq.getUByte(18) * 256) + paq.getUByte(19);
        texto += "\n\tIdentificador: 0x" + Integer.toHexString(id) + " (" + id + ")";
        int flags = paq.getUByte(20) & 0xE0; //11100000
        String s_flags = Integer.toBinaryString(flags);
        if(s_flags.length() != 8) { //No cuenta los ceros al inicio
            s_flags = fillZ(s_flags);
        }
        tempo = flagsIPv4(s_flags);
        String t_b  = String.valueOf(Integer.parseInt(s_flags.substring(0,3), 2));
        if(t_b.length() == 1) {
            t_b = '0' + t_b;
        }
        
        texto += "\n\tBanderas: 0x" + t_b + " - "+ tempo;
        int pos_frag = ((paq.getUByte(20) & 0x1F)  * 256) + paq.getUByte(21);
        texto += "\n\tPosición de Fragmento: " + pos_frag;
        int ttl = paq.getUByte(22);
        texto += "\n\tTiempo de vida: " + ttl;
        int protocol = paq.getUByte(23);
        tempo = protocoloIPv4(protocol);
        texto += "\n\tProtocolo: " + tempo + " ("+ protocol + ")";
        int checksum = (paq.getUByte(24) * 256) + paq.getUByte(25);
        texto += "\n\tChecksum de encabezado: 0x" + Integer.toHexString(checksum);
        texto += "\n\tIP Origen: " + paq.getUByte(26) + "." + paq.getUByte(27) + "."
                    + paq.getUByte(28) + "." + paq.getUByte(29);
        texto += "\n\tIP Destino: " + paq.getUByte(30) + "." + paq.getUByte(31) + "."
                    + paq.getUByte(32) + "." + paq.getUByte(33);
        
        if(protocol == 6) {tempo = esTCP(paq);} 
        else if(protocol == 17) {tempo = esUDP(paq);}
        else if(protocol == 1) { tempo = esICMP(paq);}
        else if(protocol == 89) { tempo = esOSPF(paq);}
        else {tempo = "\nProtocolo Capa Transporte Desconocido :c";}
        
        texto += tempo;
        return texto;               
    }
    
    private String protocoloIPv4(int protocol) {
        String nombre_p = "";
        if(protocol == 6) {nombre_p = "TCP";}
        else if(protocol == 17) {nombre_p = "UDP";}
        return nombre_p;
    }
    
    private String precedenciaIPv4(String cmp) {
        String prec = "";        
        if(cmp.compareTo("000") == 0) { prec = "De rutina"; } 
        else if(cmp.compareTo("001") == 0) { prec = "Prioritario"; } 
        else if(cmp.compareTo("010") == 0) { prec = "Inmediato"; } 
        else if(cmp.compareTo("011") == 0) { prec = "Relámpago"; }  
        else if(cmp.compareTo("100") == 0) { prec = "Invalidación Relámpago"; }  
        else if(cmp.compareTo("101") == 0) { prec = "Llamada Crítica"; }  
        else if(cmp.compareTo("110") == 0) { prec = "Control de Trabajo"; }  
        else if(cmp.compareTo("111") == 0) { prec = "Control de red"; } 
        
        return prec;
    }
    
    private String caracServIPv4(String cmp) {
        String carac = "Retardo: ";        
        if(cmp.charAt(0) == '0') { carac += "Normal"; } else { carac += "Bajo";}
        carac += ", Rendimiento: ";
        if(cmp.charAt(1) == '0') { carac += "Normal"; } else { carac += "Alto";}
        carac += ", Fiabilidad: ";
        if(cmp.charAt(2) == '0') { carac += "Normal"; } else { carac += "Alta";}
        
        return carac;
    }
    
    private String flagsIPv4(String flags) {
        String texto = "";
        if(flags.charAt(1) == '0') {texto += "Divisible";} else {texto += "No divisible";}
        if(flags.charAt(2) == '0') {texto += ", Último fragmento";} else {texto += ", Fragmento intermedio";}
        return texto;
    }

    private String esTCP(JPacket paq) {
        String texto = "\nEncabezado TCP\n\tPuerto Origen: ";
        String aux1, aux2;
        int puerto_o = (paq.getUByte(34) * 256) + paq.getUByte(35);
        texto += puerto_o;
        int puerto_d = (paq.getUByte(36) * 256) + paq.getUByte(37);
        texto += "\n\tPuerto Destino: " + puerto_d;
        int num_seq1 = (paq.getUByte(38) * 256) + paq.getUByte(39);
        int num_seq2 = (paq.getUByte(40) * 256) + paq.getUByte(41);
        aux1 = Integer.toHexString(num_seq1);
        aux2 = Integer.toHexString(num_seq2);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++) {
                aux1 = '0' + aux1;
            }
        }
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0 ; i < tmp ; i++) {
                aux2 = '0' + aux2;
            }
        }
        texto += "\n\tNúmero de Secuencia: 0x" + aux1 + aux2;
        int num_ack1 = (paq.getUByte(42) * 256) + paq.getUByte(43);
        int num_ack2 = (paq.getUByte(44) * 256) + paq.getUByte(45);
        aux1 = Integer.toHexString(num_ack1);
        aux2 = Integer.toHexString(num_ack2);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++) {
                aux1 = '0' + aux1;
            }
        }
        if(aux2.length() < 4) {
            int tmp = 4 - aux2.length();
            for(int i = 0 ; i < tmp ; i++) {
                aux2 = '0' + aux2;
            }
        }        
        texto += "\n\tNúmero de Acuse: 0x" + aux1 + aux2;
        int hlen = paq.getUByte(46) >> 4;
        texto += "\n\tLongitud de Encabezado: " + (hlen * 4) + " bytes";
        String flags = Integer.toBinaryString(paq.getUByte(47));
        if(flags.length() != 8) {
            flags = fillZ(flags);
        }
        aux1 = flagsTCP(flags.substring(2));
        texto += "\n\tBanderas: " + aux1;
        int tam_ventana = (paq.getUByte(48) * 256) + paq.getUByte(49);
        texto += "\n\tTamaño de Ventana: " + tam_ventana;
        int tcp_checksum = (paq.getUByte(50) * 256) + paq.getUByte(51);
        aux1 = Integer.toHexString(tcp_checksum);
        if(aux1.length() < 4) {
            int tmp = 4 - aux1.length();
            for(int i = 0 ; i < tmp ; i++) {aux1 = '0' + aux1;}
        }
        texto += "\n\tChecksum TCP: 0x" + aux1;
        
        return texto;
    }
    
    private String flagsTCP(String flags) {
        String texto = "\n\t\tURG: ";
        if(flags.charAt(0) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", ACK: ";
        if(flags.charAt(1) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", PSH: ";
        if(flags.charAt(2) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", RST: ";
        if(flags.charAt(3) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", SYN: ";
        if(flags.charAt(4) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        texto += ", FIN: ";
        if(flags.charAt(5) == '0') {texto += "Apagada";} else {texto += "Prendida";}
        
        return texto;
    }
    
    private String esUDP(JPacket paq) {
        String texto = "\nEncabezado UDP\n\tPuerto Origen: ";
        String aux;
        int puerto_o = (paq.getUByte(34) * 256) + paq.getUByte(35);
        texto += puerto_o + "\n\tPuerto Destino: ";
        int puerto_d = (paq.getUByte(36) * 256) + paq.getUByte(37);
        texto += puerto_d + "\n\tLongitud de Encabezado: ";
        int udp_len = (paq.getUByte(38) * 256) + paq.getUByte(39);
        texto += udp_len + "\n\tChecksum UDP: 0x";
        int udp_checksum = (paq.getUByte(40) * 256) + paq.getUByte(41);
        aux = Integer.toHexString(udp_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux;
        return texto;
    }
    
    private String esICMP(JPacket paq) {
        String texto = "\nEncabezado ICMP\n\tTipo: ", aux;
        int tipo = paq.getUByte(34);
        texto += tipo + "\n\tCódigo: ";
        int codigo = paq.getUByte(35);
        texto += codigo + " (";
        String auxCode = "";
        
        switch(tipo) {
            case 0: auxCode = code0and8ICMP(); break;
            case 3: auxCode = code3ICMP(codigo); break;  
            case 8: auxCode = code0and8ICMP(); break;
            case 11: auxCode = code11ICMP(codigo); break;
        }        
        texto += auxCode + "\n\tChecksum ICMP: 0x";
        int icmp_checksum = (paq.getUByte(36) * 256) + paq.getUByte(37);
        aux = Integer.toHexString(icmp_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux + "\n";
        switch(tipo) {
            case 0: auxCode = code0and8ICMP(paq); break;
            case 3: auxCode = "\tSin Uso: 0x0000"; break;
            case 8: auxCode = code0and8ICMP(paq); break;
            case 11: auxCode = "\tSin Uso: 0x0000"; break;
        }                
        
        texto += auxCode;
        return texto;
    }
    
    private String code0and8ICMP() {
        String texto = ")";        
        return texto;
    }
    
    private String code0and8ICMP(JPacket paq) { // 38
        String texto = "\tIdentificador: ", aux;
        int identificador = (paq.getUByte(38) * 256) + paq.getUByte(39);
        texto += identificador + " (0x";
        aux = Integer.toHexString(identificador);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux + ")\n\tNumero de Secuencia: ";
        int seqNum = (paq.getUByte(40) * 256) + paq.getUByte(41);
        aux = Integer.toHexString(seqNum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(int i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += seqNum + " (0x" + aux + ")";
        texto += "\n\tDatos: \n\t"; aux = "";
        for(int i = 0; i < 32; i++) {
            aux += Integer.toHexString(paq.getUByte(42 + i));
        }
        texto += aux;
        
        
        return texto;
    }
    private String code3ICMP(int codigo) {
        String texto = "";
        switch(codigo) {
            case 0: texto += "Red inaccesible)"; break;
            case 1: texto += "Host inaccesible)"; break;
            case 2: texto += "Protocolo inaccesible)"; break;
            case 3: texto += "Puerto inaccesible)"; break;
            case 4: texto += "DF activado)"; break;
            case 5: texto += "Fallo ruta origen)"; break;
            default: texto += "Desconocido)"; break;            
        }
        
        return texto;
    }    
    
    private String code11ICMP(int codigo) {
        String texto = "";
        if(codigo == 0) {
            texto += "TTL excedido en tránsito";
        } else {
            texto += "Tiempo de reensamblado excedido";
        }
        return texto;
    }
    
    private String esOSPF(JPacket paq) {
        int i;
        String texto = "\nEncabezado OSPF\n\tVersión OSPF: ";      
        int version = paq.getUByte(34);
        texto += version + "\n\tTipo de Mensaje: ";
        int tipo = paq.getUByte(35);
        texto += tipoOSPF(tipo);
        int longitud_OSPF = (256 * paq.getUByte(36)) + paq.getUByte(37);
        texto += "\n\tLongitud de Paquete: " + longitud_OSPF;
        texto += "\n\tID Router: ";
        int router_id[] = new int[4];
        for(i = 0; i < 4; i++) { // 38 - 41
            router_id[i] = paq.getUByte(38 + i);
            if(i != 3) {
                texto += router_id[i] + ".";
            }
        }
        texto += router_id[i];
        texto += "\n\tID Area: ";
        int area_id[] = new int[4];
        for(i = 0; i < 4; i++) { // 42 - 45
            area_id[i] = paq.getUByte(42 + i);
            if(i != 3) {
                texto += area_id[i] + ".";
            }
        }
        texto += area_id[i];
        texto += "\n\tChecksum: 0x";
        int ospf_checksum = (paq.getUByte(46) * 256) + paq.getUByte(47);
        String aux = Integer.toHexString(ospf_checksum);
        if(aux.length() < 4) {
            int tmp = 4 - aux.length();
            for(i = 0 ; i < tmp ; i++) {aux = '0' + aux;}
        }
        texto += aux + "\n\tTipo de Autenticación: ";
        int tipAu = paq.getUByte(48);
        texto += tipAuOSPF(tipAu);
        /* Aquí es ver si se añade lo de HELLO MSG */ 
        return texto;
    }

    private String tipoOSPF(int tipo) {
        String texto;
        switch(tipo) {
            case 1: texto = "Saludo (" + tipo + ")"; break;
            case 2: texto = "DBD (" + tipo + ")"; break;
            case 3: texto = "LSR (" + tipo + ")"; break;
            case 4: texto = "LSU (" + tipo + ")"; break;
            case 5: texto = "LSAck (" + tipo + ")"; break;
            default: texto = "Desconocido :c "; break;
        }
        return texto;
    }
    
    private String tipAuOSPF(int tipo) {
        String texto;
        switch(tipo) {
            case 0: texto = "Sin Autenticacion."; break;
            case 1: texto = "Texto Claro."; break;
            case 2: texto = "MOS"; break;
            default: texto = "Desconocido :c"; break;
        }
        return texto;
    }
    
    private String fillZ (String binary) {
        int t_ctrl = 8 - binary.length();
        String tempo = "";
        for(int b = 0 ; b < t_ctrl ; b++) {
            tempo = tempo.concat("0");
        }                             
        tempo = tempo.concat(binary);
        binary = tempo.substring(0);
        
        return binary;
    }
}