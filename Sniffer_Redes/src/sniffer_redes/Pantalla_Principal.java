/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sniffer_redes;

import com.sun.awt.AWTUtilities;
import java.awt.Shape;
import java.awt.geom.RoundRectangle2D;


public class Pantalla_Principal extends javax.swing.JFrame {

    /**
     * Creates new form Pantalla_Principal
     */
    public Pantalla_Principal() {
        initComponents();
        this.setLocationRelativeTo(null);
        Shape forma = new RoundRectangle2D.Double(0, 0, this.getBounds().width, this.getBounds().height, 30, 30);
        AWTUtilities.setWindowShape(this, forma);
        
        btnGenerar.setToolTipText("Generar paquetes.");
        btnAnalizar.setToolTipText("Analizar paquetes.");
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jSeparator1 = new javax.swing.JSeparator();
        jLabel2 = new javax.swing.JLabel();
        btnGenerar = new javax.swing.JButton();
        btnAnalizar = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setUndecorated(true);
        getContentPane().setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

        jLabel2.setFont(new java.awt.Font("Copperplate Gothic Bold", 1, 24)); // NOI18N
        jLabel2.setForeground(new java.awt.Color(25, 25, 112));
        jLabel2.setText("Sniffer");
        getContentPane().add(jLabel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(110, 20, 120, -1));

        btnGenerar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/imagenes/generar (2).png"))); // NOI18N
        btnGenerar.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnGenerarMouseEntered(evt);
            }
        });
        btnGenerar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnGenerarActionPerformed(evt);
            }
        });
        getContentPane().add(btnGenerar, new org.netbeans.lib.awtextra.AbsoluteConstraints(220, 60, 60, 60));

        btnAnalizar.setIcon(new javax.swing.ImageIcon(getClass().getResource("/imagenes/analisis.png"))); // NOI18N
        btnAnalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAnalizarActionPerformed(evt);
            }
        });
        getContentPane().add(btnAnalizar, new org.netbeans.lib.awtextra.AbsoluteConstraints(60, 60, 60, 60));

        jLabel1.setBackground(new java.awt.Color(255, 240, 245));
        jLabel1.setIcon(new javax.swing.ImageIcon(getClass().getResource("/sniffer_redes/Fondo.png"))); // NOI18N
        jLabel1.setText("jLabel1");
        getContentPane().add(jLabel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(0, 0, 340, 170));

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void btnGenerarMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnGenerarMouseEntered
        btnGenerar.setToolTipText("Generar paquete");
    }//GEN-LAST:event_btnGenerarMouseEntered

    private void btnGenerarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnGenerarActionPerformed
        
    }//GEN-LAST:event_btnGenerarActionPerformed

    private void btnAnalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAnalizarActionPerformed
        this.dispose();
        Menu_Captura gp = new Menu_Captura();
        gp.setVisible(true); 
    }//GEN-LAST:event_btnAnalizarActionPerformed

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
            java.util.logging.Logger.getLogger(Pantalla_Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(Pantalla_Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(Pantalla_Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(Pantalla_Principal.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new Pantalla_Principal().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnAnalizar;
    private javax.swing.JButton btnGenerar;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JSeparator jSeparator1;
    // End of variables declaration//GEN-END:variables
}