package org.AF.SharePointUtilities.UploadFileToSP;

import java.util.Arrays;
import java.util.HashMap;

import javax.swing.JFileChooser;

import org.knime.core.node.FlowVariableModel;
import org.knime.core.node.InvalidSettingsException;
import org.knime.core.node.NodeSettingsRO;
import org.knime.core.node.NodeSettingsWO;
import org.knime.core.node.NotConfigurableException;
import org.knime.core.node.defaultnodesettings.DefaultNodeSettingsPane;
import org.knime.core.node.defaultnodesettings.DialogComponentAuthentication;
import org.knime.core.node.defaultnodesettings.DialogComponentNumber;
import org.knime.core.node.defaultnodesettings.DialogComponentString;
import org.knime.core.node.defaultnodesettings.DialogComponentStringSelection;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication.AuthenticationType;
import org.knime.core.node.defaultnodesettings.SettingsModelIntegerBounded;
import org.knime.core.node.defaultnodesettings.SettingsModelString;
import org.knime.core.node.port.PortObjectSpec;
import org.knime.core.node.workflow.FlowVariable.Type;
import org.knime.core.util.Pair;
import org.knime.filehandling.core.defaultnodesettings.DialogComponentFileChooser2;
import org.knime.filehandling.core.defaultnodesettings.SettingsModelFileChooser2;



/**
 * This is an example implementation of the node dialog of the
 * "UploadFileToSP" node.
 *
 * This node dialog derives from {@link DefaultNodeSettingsPane} which allows
 * creation of a simple dialog with standard components. If you need a more
 * complex dialog please derive directly from
 * {@link org.knime.core.node.NodeDialogPane}. In general, one can create an
 * arbitrary complex dialog using Java Swing.
 * 
 * @author Another Fraud
 */
public class UploadFileToSPNodeDialog extends DefaultNodeSettingsPane {



	private final SettingsModelAuthentication clientTokenModel;
	private final SettingsModelAuthentication proxyAuth;

	private final DialogComponentAuthentication m_authenticationTokenPanel;
	private final DialogComponentAuthentication m_authenticationProxyPanel;
	

	/**
	 * New dialog pane for configuring the node. The dialog created here
	 * will show up when double clicking on a node in KNIME Analytics Platform.
	 */
    protected UploadFileToSPNodeDialog() {
        super();
        
        proxyAuth = UploadFileToSPNodeModel.createProxySettingsModel();
        
       	clientTokenModel = UploadFileToSPNodeModel.createClientTokenSettingsModel();
       	final SettingsModelString useProxyModel = UploadFileToSPNodeModel.createUseProxySettingsModel();
       	final SettingsModelIntegerBounded proxyPort = UploadFileToSPNodeModel.createProxyPortIndexModel();
       	final SettingsModelString proxyHost = UploadFileToSPNodeModel.createProxyHostSettingsModel();
       	final SettingsModelString sharePointOnlineSiteURLModel = UploadFileToSPNodeModel.createSharePointUrlSettingsModel();
        final SettingsModelFileChooser2 uploadFilePathModel2 = UploadFileToSPNodeModel.createUploadFilePath2SettingsModel();
        final SettingsModelString spFolderPathModel = UploadFileToSPNodeModel.createSpFolderPathSettingsModel();
        final SettingsModelString sharePointNameModel = UploadFileToSPNodeModel.createSharePointNameSettingsModel();
 
        
       	//Map<AuthenticationType, Pair<String, String>> map;
       	HashMap<AuthenticationType, Pair<String, String>> map = new HashMap<AuthenticationType, Pair<String, String>>()
       	{/**
			 * 
			 */
			private static final long serialVersionUID = 8655322170602238215L;

		{
       	     put(AuthenticationType.CREDENTIALS, new Pair<String, String>("Client Token Credential","Client Token Credentials"));
       	     put(AuthenticationType.PWD, new Pair<String, String>("Client Token String","Client Token String"));

       	}};
       	
       	//Map<AuthenticationType, Pair<String, String>> map;
       	HashMap<AuthenticationType, Pair<String, String>> mapProxy = new HashMap<AuthenticationType, Pair<String, String>>()
       	{/**
			 * 
			 */
			private static final long serialVersionUID = 4293690106264795303L;

		{
       	     put(AuthenticationType.CREDENTIALS, new Pair<String, String>("Proxy Login Credential","Proxy Login Credentials"));
       	     put(AuthenticationType.PWD, new Pair<String, String>("Proxy User/Password","Proxy User/Password"));

       	}};      	
        m_authenticationTokenPanel = new  DialogComponentAuthentication(clientTokenModel, "Client Token", Arrays.asList(AuthenticationType.CREDENTIALS, AuthenticationType.PWD), map);    	
        m_authenticationProxyPanel = new  DialogComponentAuthentication(proxyAuth, "Proxy User/Password", Arrays.asList(AuthenticationType.CREDENTIALS, AuthenticationType.USER_PWD), mapProxy);
        
       	
        //listener check selection for password usage
       	useProxyModel.addChangeListener(e -> {
            if (useProxyModel.getStringValue().equals("Use Proxy")) {
            	proxyAuth.setEnabled(true);
            	proxyPort.setEnabled(true);
            	proxyHost.setEnabled(true);
            	
            }
            else  {
            	proxyAuth.setEnabled(false);
            	proxyPort.setEnabled(false);
            	proxyHost.setEnabled(false);
            }
        });  
       	
       	
       	
       	createNewGroup("General Information"); 
       	
       	addDialogComponent(new DialogComponentString(sharePointOnlineSiteURLModel, "SharePoint Online Site URL", true, 60));
       	addDialogComponent(new DialogComponentString(sharePointNameModel, "SharePoint Site Name", true, 60));
       	addDialogComponent(new DialogComponentString(spFolderPathModel, "Upload into Sp Folder (complete path)", true, 60));


       	

       	
       	addDialogComponent(m_authenticationTokenPanel);
       	;
       	
       	
       	
        final FlowVariableModel fvm = createFlowVariableModel(
                new String[]{uploadFilePathModel2.getConfigName(), SettingsModelFileChooser2.PATH_OR_URL_KEY},
                Type.STRING);

            
            addDialogComponent(new DialogComponentFileChooser2(0, uploadFilePathModel2, "UploadFile", JFileChooser.OPEN_DIALOG,
                JFileChooser.FILES_ONLY, fvm));
            
        
        closeCurrentGroup();
        
        
        
		
        createNewTab("Proxy Options");
        createNewGroup("Proxy Options"); 
        
        addDialogComponent(
        new DialogComponentStringSelection(useProxyModel, "Proxy Config",
        		Arrays.asList( "no Proxy","Use Proxy"),false));
        
        
        addDialogComponent(new DialogComponentString(proxyHost, "Proxy Host", true, 30));
        addDialogComponent(new DialogComponentNumber(proxyPort, "Proxy Port", 1));
        
        
        
        addDialogComponent(m_authenticationProxyPanel);

        closeCurrentGroup();
 
        
        
    }
    

    @Override
    public void saveAdditionalSettingsTo(final NodeSettingsWO settings) throws InvalidSettingsException {
    	clientTokenModel.saveSettingsTo(settings);
    	proxyAuth.saveSettingsTo(settings);
    	
    	
    }

    @Override
    public void loadAdditionalSettingsFrom(final NodeSettingsRO settings,
            final PortObjectSpec[] specs) throws NotConfigurableException {
    	try {
    		clientTokenModel.loadSettingsFrom(settings);
    		proxyAuth.loadSettingsFrom(settings);
    		m_authenticationTokenPanel.loadSettingsFrom(settings, specs, getCredentialsProvider());
    		m_authenticationProxyPanel.loadSettingsFrom(settings, specs, getCredentialsProvider());
    	} catch (InvalidSettingsException e) {
    		throw new NotConfigurableException(e.getMessage(), e);
    	}
    }


}

