package org.AF.KeepassUtilities.KeepassReader;

import java.util.Arrays;

import javax.swing.JFileChooser;

import org.knime.core.node.FlowVariableModel;
import org.knime.core.node.defaultnodesettings.DefaultNodeSettingsPane;
import org.knime.core.node.defaultnodesettings.DialogComponentAuthentication;
import org.knime.core.node.defaultnodesettings.DialogComponentButton;
import org.knime.core.node.defaultnodesettings.DialogComponentStringSelection;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication.AuthenticationType;
import org.knime.core.node.defaultnodesettings.SettingsModelString;
import org.knime.core.node.workflow.FlowVariable.Type;
import org.knime.filehandling.core.defaultnodesettings.DialogComponentFileChooser2;
import org.knime.filehandling.core.defaultnodesettings.SettingsModelFileChooser2;

/**
 * This is an example implementation of the node dialog of the
 * "KeepassReader" node.
 *
 * This node dialog derives from {@link DefaultNodeSettingsPane} which allows
 * creation of a simple dialog with standard components. If you need a more
 * complex dialog please derive directly from
 * {@link org.knime.core.node.NodeDialogPane}. In general, one can create an
 * arbitrary complex dialog using Java Swing.
 * 
 * @author AnotherFraudUser
 */
public class KeepassReaderNodeDialog extends DefaultNodeSettingsPane {

	/**
	 * New dialog pane for configuring the node. The dialog created here
	 * will show up when double clicking on a node in KNIME Analytics Platform.
	 */
    protected KeepassReaderNodeDialog() {
        super();

        
       

        	
        	final SettingsModelString keepassEntryNameModel = KeepassReaderNodeModel.createKeepassEntryNamesModel();
            final SettingsModelFileChooser2 inputFilePathModel2 = KeepassReaderNodeModel.createInputFilePath2SettingsModel();
            final SettingsModelAuthentication passwordModel = KeepassReaderNodeModel.createPassSettingsModel();
            
            final DialogComponentButton loadEntrys = new DialogComponentButton("Load entrys from file");
            final DialogComponentStringSelection sheetNameSelection = new DialogComponentStringSelection(keepassEntryNameModel, "Entry Name",
            		Arrays.asList("default", ""),true);


            
            
            createNewGroup("File Selection");
            

            final FlowVariableModel fvm = createFlowVariableModel(
                new String[]{inputFilePathModel2.getConfigName(), SettingsModelFileChooser2.PATH_OR_URL_KEY},
                Type.STRING);

            addDialogComponent(new DialogComponentFileChooser2(0, inputFilePathModel2, "templateFile", JFileChooser.OPEN_DIALOG,
                    JFileChooser.FILES_ONLY, fvm));
            
            
            createNewGroup("Entry Selection");
            
            addDialogComponent(loadEntrys);
            addDialogComponent(sheetNameSelection); 
            
            
               
            createNewGroup("Keepass Password");
            addDialogComponent(new  DialogComponentAuthentication(passwordModel, "Keepass Store Password", AuthenticationType.PWD));

            
            
            closeCurrentGroup();
            
       	   
      
           
            
            
        }


        
    }


