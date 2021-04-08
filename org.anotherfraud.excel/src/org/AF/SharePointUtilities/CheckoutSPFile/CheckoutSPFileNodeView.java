package org.AF.SharePointUtilities.CheckoutSPFile;

import org.knime.core.node.NodeView;


/**
 * This is an example implementation of the node view of the
 * "CheckoutSPFile" node.
 * 
 * As this example node does not have a view, this is just an empty stub of the 
 * NodeView class which not providing a real view pane.
 *
 * @author Another Fraud
 */
public class CheckoutSPFileNodeView extends NodeView<CheckoutSPFileNodeModel> {

    /**
     * Creates a new view.
     * 
     * @param nodeModel The model (class: {@link CheckoutSPFileNodeModel})
     */
    protected CheckoutSPFileNodeView(final CheckoutSPFileNodeModel nodeModel) {
        super(nodeModel);

        // TODO instantiate the components of the view here.

    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void modelChanged() {

        // TODO retrieve the new model from your nodemodel and 
        // update the view.
        CheckoutSPFileNodeModel nodeModel = 
            (CheckoutSPFileNodeModel)getNodeModel();
        assert nodeModel != null;
        
        // be aware of a possibly not executed nodeModel! The data you retrieve
        // from your nodemodel could be null, emtpy, or invalid in any kind.
        
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void onClose() {
    
        // TODO things to do when closing the view
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void onOpen() {

        // TODO things to do when opening the view
    }

}

