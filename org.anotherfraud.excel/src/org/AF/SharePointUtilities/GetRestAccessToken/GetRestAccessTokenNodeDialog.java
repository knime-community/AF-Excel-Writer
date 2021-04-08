package org.AF.SharePointUtilities.GetRestAccessToken;


import java.util.Arrays;

import org.knime.core.node.defaultnodesettings.DefaultNodeSettingsPane;
import org.knime.core.node.defaultnodesettings.DialogComponentAuthentication;
import org.knime.core.node.defaultnodesettings.DialogComponentNumber;
import org.knime.core.node.defaultnodesettings.DialogComponentString;
import org.knime.core.node.defaultnodesettings.DialogComponentStringSelection;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication;
import org.knime.core.node.defaultnodesettings.SettingsModelIntegerBounded;
import org.knime.core.node.defaultnodesettings.SettingsModelString;
import org.knime.core.node.defaultnodesettings.SettingsModelAuthentication.AuthenticationType;

/**
 * This is an example implementation of the node dialog of the
 * "GetRestAccessToken" node.
 *
 * This node dialog derives from {@link DefaultNodeSettingsPane} which allows
 * creation of a simple dialog with standard components. If you need a more
 * complex dialog please derive directly from
 * {@link org.knime.core.node.NodeDialogPane}. In general, one can create an
 * arbitrary complex dialog using Java Swing.
 * 
 * @author AnotherFraud
 */
public class GetRestAccessTokenNodeDialog extends DefaultNodeSettingsPane {

	/**
	 * New dialog pane for configuring the node. The dialog created here
	 * will show up when double clicking on a node in KNIME Analytics Platform.
	 */
    protected GetRestAccessTokenNodeDialog() {
        super();
        
        final SettingsModelAuthentication proxyAuth = GetRestAccessTokenNodeModel.createProxySettingsModel();
                
       	final SettingsModelString clientIDModel = GetRestAccessTokenNodeModel.createClientIDSettingsModel();
       	final SettingsModelAuthentication clientSecretModel = GetRestAccessTokenNodeModel.createClientSecretSettingsModel();
       	final SettingsModelString tennantIDModel = GetRestAccessTokenNodeModel.createTennantIDSettingsModel();
       	final SettingsModelString useProxyModel = GetRestAccessTokenNodeModel.createUseProxySettingsModel();
       	final SettingsModelIntegerBounded proxyPort = GetRestAccessTokenNodeModel.createProxyPortIndexModel();
       	final SettingsModelString proxyHost = GetRestAccessTokenNodeModel.createProxyHostSettingsModel();
       	final SettingsModelString sharePointOnlineSiteURL = GetRestAccessTokenNodeModel.createSharePointUrlSettingsModel();
       	
       	
       	
       	
       	
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
       	
       	
       	
       	addDialogComponent(new DialogComponentString(clientIDModel, "Client ID", true, 30));
       	addDialogComponent(new DialogComponentString(tennantIDModel, "Tennant ID", true, 30));
       	addDialogComponent(new DialogComponentString(sharePointOnlineSiteURL, "SharePoint Online Site URL", true, 60));
        addDialogComponent(new  DialogComponentAuthentication(clientSecretModel, "Client Secret", AuthenticationType.PWD));

		
        
        
        
		
        createNewTab("Proxy Options");
        createNewGroup("Proxy Options"); 
        
        addDialogComponent(
        new DialogComponentStringSelection(useProxyModel, "Proxy Config",
        		Arrays.asList( "no Proxy","Use Proxy"),false));
        
        
        addDialogComponent(new DialogComponentString(proxyHost, "Proxy Host", true, 30));
        addDialogComponent(new DialogComponentNumber(proxyPort, "Proxy Port", 1));
        
        addDialogComponent(new  DialogComponentAuthentication(proxyAuth, "Proxy User/Password", AuthenticationType.USER_PWD));

        closeCurrentGroup();
        
        
    }
}

