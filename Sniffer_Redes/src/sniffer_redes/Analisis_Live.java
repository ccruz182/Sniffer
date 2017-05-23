package sniffer_redes;

import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Scanner;
import javax.swing.SwingWorker;
import javax.swing.table.DefaultTableModel;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

public class Analisis_Live extends javax.swing.JFrame {
    DefaultTableModel modeloP = new DefaultTableModel() {@Override
    public boolean isCellEditable(int rowIndex, int colIndex) { return false; } };
    Scanner entrada = new Scanner(System.in);    
    private ArrayList <JPacket> paq = new ArrayList<>();
    private Pcap pcap;
    private int num = 0;
    
    final int IPV4 = 2048;
    final int ARP = 2054;
    final int IPV6 = 34525;
    
    
    public Analisis_Live() {
        initComponents();
        modeloP.addColumn("Número");
        modeloP.addColumn("MAC Fuente");
        modeloP.addColumn("MAC Destino");
        modeloP.addColumn("Tipo");
        modeloP.addColumn("Longitud Total");  
        tableTramas.setModel(modeloP);
        tableTramas.getColumnModel().getColumn(0).setMaxWidth(60);
    }

    private void analisis() {
        List<PcapIf> alldevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
  
        /*************************************************************************** 
         * First get a list of devices on this system 
         **************************************************************************/  
        int r = Pcap.findAllDevs(alldevs, errbuf);  
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {  
            System.err.printf("Can't read list of devices, error is %s", errbuf  
                .toString());  
            return;  
        }  
  
        System.out.println("Network devices found:");  
  
        int i = 0;  
        for (PcapIf device : alldevs) {  
            String description =  
                (device.getDescription() != null) ? device.getDescription()  
                    : "No description available";  
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);  
        }  
        //System.out.println("Enter the device: ");
        //int a = entrada.nextInt();
        PcapIf device = alldevs.get(0); // We know we have atleast 1 device  
        /*System.out  
            .printf("\nChoosing '%s' on your behalf:\n",  
                (device.getDescription() != null) ? device.getDescription()  
                    : device.getName());*/  
  
        /*************************************************************************** 
         * Second we open up the selected device 
         **************************************************************************/  
        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 500;           // 10 seconds in millis  
        /*Pcap */ pcap =  
            Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);  
  
        if (pcap == null) {  
            System.err.printf("Error while opening device for capture: "  
                + errbuf.toString());  
            return;  
        }  
  
        /*************************************************************************** 
         * Third we create a packet handler which will receive packets from the 
         * libpcap loop. 
         **************************************************************************/  
        PcapPacketHandler<String> jpacketHandler = (PcapPacket packet, String user) -> {
            String tabla[] = new String[5];
            System.out.printf("Received packet at %s caplen=%-4d len=%-4d %s\n",
                    new Date(packet.getCaptureHeader().timestampInMillis()),
                    packet.getCaptureHeader().caplen(),  // Length actually captured
                    packet.getCaptureHeader().wirelen(), // Original length
                    user                                 // User supplied object
            );
            paq.add(packet);
            String tempo = "";
            /* Se llenan los campos de la tabla */
            tabla[0] = String.valueOf(num);
            for (int i1 = 0; i1 < 6; i1++) {
                tempo = tempo.concat(String.format("%02X", packet.getUByte(i1)));
                tempo = tempo.concat(" ");
            }
            tabla[1] = tempo;
            /* Columna 2 */
            tempo = "";
            for (int i2 = 6; i2 < 12; i2++) {
                tempo = tempo.concat(String.format("%02X", packet.getUByte(i2)));
                tempo = tempo.concat(" ");
            }
            tabla[2] = tempo;
            /* Columna 3 */
            String tempo_1;
            int tipo = (packet.getUByte(12) * 256 ) + (packet.getUByte(13));
            if(String.valueOf(packet.getUByte(12)).length() == 1) {
                tempo_1 = '0' + String.valueOf(packet.getUByte(12));
            } else {
                tempo_1 = Integer.toHexString(packet.getUByte(12));
            }
            if(String.valueOf(packet.getUByte(13)).length() == 1) {
                tempo_1 = '0' + String.valueOf(packet.getUByte(13));
            } else {
                tempo_1 = Integer.toHexString(packet.getUByte(13));
            }
            if(tipo > 1500) {
                /* Ethernet */
                tabla[3] = "Ethernet";
            } else {
                /* IEEE */
                tabla[3] = "IEEE";
            }
            /* Columna 4 */
            tabla[4] = String.valueOf(packet.size()) + " bytes";
            /* Se añade en tabla */
            modeloP.addRow(tabla);
            tableTramas.setModel(modeloP);
            num++;  
        };             
        pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jNetPcap rocks!");    
        pcap.close();  
    }
    
    private void mostrarInfo(){
        int fila_selec = tableTramas.getSelectedRow();        
        JPacket pakete = paq.get(fila_selec);         
        Aux_Live auxiliar = new Aux_Live(pakete);
        String texto = "";
        String type = "Unknown";
        if(fila_selec != -1) {                       
            if(auxiliar.getTipo() > 1500) {
                /* ETHERNET */
                texto = texto + "ETHERNET\n";
       
                texto = texto + "\tMAC Destino:\t" + auxiliar.getMacd();
                texto = texto + ".\n";
                texto = texto + "\tMAC Origen:\t" + auxiliar.getMaco();
                texto = texto + ".\n";               
              
                String temp_red = "";
                switch (auxiliar.getTipo()) {
                    case IPV4:
                        type = "IPv4";
                        Informacion_IPv4 info_ipv4 = new Informacion_IPv4(pakete);
                        temp_red = info_ipv4.getInformacionDetallada();
                        break;
                    case ARP:
                        type = "ARP";
                        Informacion_ARP info_arp = new Informacion_ARP(pakete);
                        temp_red = info_arp.getInformacionDetallada();
                        break;
                    case IPV6:
                        type = "IPv6";                
                        break;
                    default:
                        break;
                }
               texto = texto + "\tTipo:\t" + type + " (0x"+ auxiliar.getTipo_byte1() + auxiliar.getTipo_byte2() + ")";      
               texto += temp_red;
               areaInformacion.setText(texto);
            } 
            else { /* ES IEEE */
               Informacion_LLC iL = new Informacion_LLC();
               areaInformacion.setText(iL.impresionInformacion(pakete));
            }
        }
    }
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        tableTramas = new javax.swing.JTable();
        btnCapturar = new javax.swing.JButton();
        btnStop = new javax.swing.JButton();
        jScrollPane2 = new javax.swing.JScrollPane();
        areaInformacion = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        tableTramas.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null},
                {null, null, null, null, null}
            },
            new String [] {
                "Número", "MAC Fuente", "MAC Destino", "Tipo", "Longitud Total"
            }
        ));
        tableTramas.setAutoResizeMode(javax.swing.JTable.AUTO_RESIZE_ALL_COLUMNS);
        tableTramas.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mousePressed(java.awt.event.MouseEvent evt) {
                tableTramasMousePressed(evt);
            }
        });
        tableTramas.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyPressed(java.awt.event.KeyEvent evt) {
                tableTramasKeyPressed(evt);
            }
        });
        jScrollPane1.setViewportView(tableTramas);

        btnCapturar.setText("Capturar");
        btnCapturar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCapturarActionPerformed(evt);
            }
        });

        btnStop.setText("Stop");
        btnStop.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnStopActionPerformed(evt);
            }
        });

        areaInformacion.setColumns(20);
        areaInformacion.setRows(5);
        jScrollPane2.setViewportView(areaInformacion);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(btnCapturar)
                        .addGap(56, 56, 56)
                        .addComponent(btnStop)
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jScrollPane2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 820, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, 820, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 104, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 25, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(btnCapturar)
                    .addComponent(btnStop))
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void tableTramasMousePressed(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_tableTramasMousePressed
        mostrarInfo();
    }//GEN-LAST:event_tableTramasMousePressed

    private void btnCapturarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCapturarActionPerformed
        final SwingWorker worker = new SwingWorker() {
            @Override
            protected Object doInBackground() throws Exception {
                analisis();
                return null;
            }
        };
        worker.execute();
    }//GEN-LAST:event_btnCapturarActionPerformed

    private void btnStopActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnStopActionPerformed
        pcap.breakloop();
    }//GEN-LAST:event_btnStopActionPerformed

    private void tableTramasKeyPressed(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_tableTramasKeyPressed
        if(evt.getKeyCode()==KeyEvent.VK_DOWN || evt.getKeyCode()==KeyEvent.VK_UP){
            mostrarInfo();
        }
    }//GEN-LAST:event_tableTramasKeyPressed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Analisis_Live.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(() -> {
            new Analisis_Live().setVisible(true);
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea areaInformacion;
    private javax.swing.JButton btnCapturar;
    private javax.swing.JButton btnStop;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTable tableTramas;
    // End of variables declaration//GEN-END:variables
}
