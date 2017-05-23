package sniffer_redes;

public class Opciones extends javax.swing.JFrame {
    public Opciones() {
        initComponents();
    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTabbedPane = new javax.swing.JTabbedPane();
        jPanelEntrada = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTableEntrada = new javax.swing.JTable();
        jPanelSalida = new javax.swing.JPanel();
        jPanelOpciones = new javax.swing.JPanel();
        jCheckBoxPromiscuo = new javax.swing.JCheckBox();
        jLabelFilter = new javax.swing.JLabel();
        jTextFieldFilter = new javax.swing.JTextField();
        jButtonAdminInter = new javax.swing.JButton();
        jButtonComenzar = new javax.swing.JButton();
        jButtonParar = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Sniffer Captura de Interfaces");

        jTableEntrada.setModel(new javax.swing.table.DefaultTableModel(
            new Object [][] {

            },
            new String [] {
                "Interfaz", "Trafico", "Encabezado de capa", "Promiscuo", "Filtro de Captura"
            }
        ));
        jScrollPane1.setViewportView(jTableEntrada);

        javax.swing.GroupLayout jPanelEntradaLayout = new javax.swing.GroupLayout(jPanelEntrada);
        jPanelEntrada.setLayout(jPanelEntradaLayout);
        jPanelEntradaLayout.setHorizontalGroup(
            jPanelEntradaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 839, Short.MAX_VALUE)
        );
        jPanelEntradaLayout.setVerticalGroup(
            jPanelEntradaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanelEntradaLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 284, Short.MAX_VALUE))
        );

        jTabbedPane.addTab("Entrada", jPanelEntrada);

        javax.swing.GroupLayout jPanelSalidaLayout = new javax.swing.GroupLayout(jPanelSalida);
        jPanelSalida.setLayout(jPanelSalidaLayout);
        jPanelSalidaLayout.setHorizontalGroup(
            jPanelSalidaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 839, Short.MAX_VALUE)
        );
        jPanelSalidaLayout.setVerticalGroup(
            jPanelSalidaLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 295, Short.MAX_VALUE)
        );

        jTabbedPane.addTab("Salida", jPanelSalida);

        javax.swing.GroupLayout jPanelOpcionesLayout = new javax.swing.GroupLayout(jPanelOpciones);
        jPanelOpciones.setLayout(jPanelOpcionesLayout);
        jPanelOpcionesLayout.setHorizontalGroup(
            jPanelOpcionesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 839, Short.MAX_VALUE)
        );
        jPanelOpcionesLayout.setVerticalGroup(
            jPanelOpcionesLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 295, Short.MAX_VALUE)
        );

        jTabbedPane.addTab("Opciones", jPanelOpciones);

        jCheckBoxPromiscuo.setText("Habilitar el modo promiscuo en todas las interfaces");

        jLabelFilter.setText("Filtro de captura para las interfaces seleccionadas: ");

        jTextFieldFilter.setText("Inserte un filtro de captura...");
        jTextFieldFilter.setToolTipText("");

        jButtonAdminInter.setText("Administrar Interfaces...");

        jButtonComenzar.setText("Comenzar");

        jButtonParar.setText("Parar");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTabbedPane)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jCheckBoxPromiscuo)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButtonAdminInter))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabelFilter)
                        .addGap(18, 18, 18)
                        .addComponent(jTextFieldFilter, javax.swing.GroupLayout.PREFERRED_SIZE, 401, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jButtonComenzar)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jButtonParar, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jTabbedPane, javax.swing.GroupLayout.PREFERRED_SIZE, 323, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addComponent(jCheckBoxPromiscuo)
                        .addGap(18, 18, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(jButtonAdminInter)
                        .addGap(30, 30, 30)))
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabelFilter)
                    .addComponent(jTextFieldFilter, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jButtonComenzar)
                    .addComponent(jButtonParar))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

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
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(Opciones.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Opciones.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Opciones.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Opciones.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Opciones().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton jButtonAdminInter;
    private javax.swing.JButton jButtonComenzar;
    private javax.swing.JButton jButtonParar;
    private javax.swing.JCheckBox jCheckBoxPromiscuo;
    private javax.swing.JLabel jLabelFilter;
    private javax.swing.JPanel jPanelEntrada;
    private javax.swing.JPanel jPanelOpciones;
    private javax.swing.JPanel jPanelSalida;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTabbedPane jTabbedPane;
    private javax.swing.JTable jTableEntrada;
    private javax.swing.JTextField jTextFieldFilter;
    // End of variables declaration//GEN-END:variables
}
