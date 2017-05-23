package sniffer_redes;

import org.jnetpcap.packet.JPacket;

public class Informacion_LLC {
    public String impresionInformacion(JPacket paquete) {
        String texto = "/* IEEE */ \nMAC Destino: ";
        for(int i = 0; i < 6; i++){
            texto = texto.concat(String.format("%02X", paquete.getUByte(i)));
            texto = texto.concat(" ");
        }
        texto = texto + "\nMAC Origen: ";
        for(int i = 6 ; i < 12; i++){
            texto = texto.concat(String.format("%02X", paquete.getUByte(i)));
            texto = texto.concat(" ");
        }        
        int llc_length = (paquete.getUByte(12)*256) + paquete.getUByte(13);
        texto += "\nLongitud de Trama LLC: " + llc_length + " bytes";
        
        String dsap = Integer.toBinaryString(paquete.getUByte(14));
        if(dsap.charAt(dsap.length() - 1) == '0') {
            texto += "\nDSAP: " + dsap + ". Dirección Individual";
        } else {
            texto += "\nDSAP: " + dsap + ". Dirección Grupal";
        }
        
        String ssap = Integer.toBinaryString(paquete.getUByte(15));
        int flag_lsb = 0;
        if(ssap.charAt(ssap.length() - 1) == '0') {
            texto += "\nSSAP: " + ssap + ". Paquete de Comando";
        } else {
            texto += "\nSSAP: " + ssap + ". Paquete de Respuesta";
            flag_lsb = 1;
        }
        
        /* Control 8/16 bits. */
        String ns, nr, code;
        if(llc_length > 3) { //Control length = 2 bytes.
            String c1 = Integer.toBinaryString(paquete.getUByte(16));
            if(c1.length() != 8) {
                c1 = fillZ(c1);
            }
            String c2 = Integer.toBinaryString(paquete.getUByte(17));
            if(c2.length() != 8) {
                c2 = fillZ(c2);
            }
            texto += "\nBits de Control: " + c1 + c2;
            char type = c1.charAt(c1.length() - 1);
            if(type == '0') { //Information
                texto += "\nTipo: Informacion";
                nr = c2.substring(0, 7);
                ns = c1.substring(0, 7);
                texto += "\nN(S): " + ns + " N(R): " + nr; 
                texto += "\nP/F: " + c2.charAt(7);
            } else {
                char type_dif = c1.charAt(c1.length() - 2);
                if(type_dif == '0') { //Supervisory
                    texto += "\nTipo: Supervisión ";                            
                    nr = c2.substring(0, 7);
                    code = c1.substring(4, 6);
                    switch (code) {
                        case "00":
                            texto += "RR. ";
                            break;
                        case "10": //It changes!! The string is not inverted.
                            texto += "REJ. ";
                            break;
                        case "01":
                            texto += "RNR. ";
                        default:
                            texto += "SREJ. ";
                    }

                    texto += "\nN(R): " + nr;
                    texto += "\nP/F: " + c2.charAt(7);
                } else { //Unnumbered
                    texto += "\nTipo: Sin enumerar "; 
                    String tt = c1.substring(0, 3) + c1.substring(4, 6);
                    code = backwards(tt);                            
                    String name_code = getCodeUn(code, flag_lsb);
                    texto += "Nombre: " + name_code;
                }
            }

        } else { //Control length = 1 byte.
            String ctr = Integer.toBinaryString(paquete.getUByte(16));
            if(ctr.length() != 8) {
                ctr = fillZ(ctr);
            }
            char type = ctr.charAt(ctr.length() - 1);
            texto += "\nBits de Control: " + ctr;
            if(type == '0') { //Information
                texto += "\nTipo: Informacion. ";
                ns = ctr.substring(4, 7);
                nr = ctr.substring(0, 3);
                texto += "\nN(S): " + ns + " N(R): " + nr;
            } else {
                char type_dif = ctr.charAt(ctr.length() - 2);
                if(type_dif == '0') { // Supervisory
                    texto += "\nTipo: Supervisión. ";
                    code = ctr.substring(4, 6);
                    nr = ctr.substring(0, 3);
                    switch (code) {
                        case "00":
                            texto += "RR.";
                            break;
                        case "10": //It changes!! The string is not inverted.
                            texto += "REJ.";
                            break;
                        case "01":
                            texto += "RNR.";
                        default:
                            texto += "SREJ.";
                    }
                    texto += "\nN(R): " + nr;
                } else { // Unnumbered
                    texto += "\nTipo: Sin enumerar. "; 
                    String tt = ctr.substring(0, 3) + ctr.substring(4, 6);
                    code = backwards(tt);                            
                    String name_code = getCodeUn(code, flag_lsb);
                    texto += "Name: " + name_code;
                }
            }
            texto += "\nP/F: " + ctr.charAt(3);
        }
        
        return texto;
    }
    
    public String getCodeUn(String code, int flag) {
        String name = "";
        if(flag == 0) { //Command
            switch(code) {
                case "00001":
                    name = "SNRM";
                    break;
                case "11011":
                    name = "SNRME";
                    break;
                case "11000":
                    name = "SARM";
                    break;
                case "11100":
                    name = "SABM";
                    break;
                case "11110":
                    name = "SABME";
                    break;
                case "00000":
                    name = "UI";
                    break;
                case "00010":
                    name = "DISC";
                    break;
                case "11001":
                    name = "RSET";
                    break;
                case "11101":
                    name = "XID";
                    break;
                default:
                    name = "Unknown";
                    break;
            }
        } else {//Response
            switch(code) {                
                case "11000":
                    name = "DM";
                    break;               
                case "00000":
                    name = "UI";
                    break;
                case "00110":
                    name = "UA";
                    break;
                case "RD":
                    name = "DISC";
                    break;                
                case "11101":
                    name = "XID";
                    break;
                default:
                    name = "Unknown";
                    break;
            }
        }
        return name;
    }
    
    public String fillZ(String binary) {
        int t_ctrl = 8 - binary.length();
        String tempo = "";
        for(int b = 0 ; b < t_ctrl ; b++) {
            tempo = tempo.concat("0");
        }                             
        tempo = tempo.concat(binary);
        binary = tempo.substring(0);
        
        return binary;
    }
    
    public String backwards(String str) {
        int i;
        char temp;
        String temp2, back = "";
            //Programa
            for(i = str.length(); i > 0 ; i--){
                temp = str.charAt(i-1);
                temp2 = new String(new char[] {temp}); //Se hace un 'cast' para poder concatenar
                back = back.concat(temp2);
            }           
        return back;
    }
}
